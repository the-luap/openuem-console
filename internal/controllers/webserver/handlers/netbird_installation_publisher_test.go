package handlers

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/stretchr/testify/require"
)

func TestNetbirdPublisherNativeInstallationUsesExactSeparateSingleDelivery(t *testing.T) {
	h, nc, js := netbirdPublisherFixture(t)
	var calls atomic.Int32
	for _, outcome := range []string{"completed", "unconfirmed", "busy", "rejected", "withdrawn", "empty", "wrong-hash", "wrong-request", "malformed", "withhold"} {
		t.Run(outcome, func(t *testing.T) {
			at := time.Now().UTC()
			c := netbirdcommand.Command{Version: 3, Identity: netbirdcommand.Identity{DeviceID: uuid.NewString(), TenantID: 3, SiteID: 4, Individual: true, CertificateHash: strings.Repeat("a", 64)}, RequestID: uuid.NewString(), Revision: strings.Repeat("b", 64), Operation: "install", IssuedAt: at, ExpiresAt: at.Add(10 * time.Minute), Package: packageapi.Package{Schema: 1, ApprovalID: uuid.NewString(), TenantID: 3, Platform: "macos", Architecture: "arm64", Format: "pkg", PackageID: "io.netbird.client", Version: "0.78.1", URL: "https://owned.example.test/netbird.pkg?private=owned-source", Size: 1234, SHA256: strings.Repeat("c", 64)}}
			require.True(t, c.Valid())
			subject, err := netbirdcommand.Subject(c.DeviceID)
			require.NoError(t, err)
			sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
				calls.Add(1)
				decoded, err := netbirdcommand.Decode(msg.Data)
				if err != nil || decoded != c {
					_ = msg.Respond(nil)
					return
				}
				r, _ := netbirdcommand.ReceiptFor(c, "completed")
				switch outcome {
				case "unconfirmed", "busy", "rejected", "withdrawn":
					r.Status = outcome
				case "empty":
					_ = msg.Respond(nil)
					return
				case "malformed":
					_ = msg.Respond([]byte(`{"private":"owned installer diagnostics"}`))
					return
				case "withhold":
					return
				case "wrong-hash":
					r.CommandHash = strings.Repeat("f", 64)
				case "wrong-request":
					r.RequestID = uuid.NewString()
				}
				data, _ := netbirdcommand.EncodeReceipt(r)
				_ = msg.Respond(data)
			})
			require.NoError(t, err)
			defer sub.Unsubscribe()
			require.NoError(t, nc.Flush())
			ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
			defer cancel()
			r, err := h.PublishNetbirdInstallation(ctx, c)
			if outcome == "completed" || outcome == "unconfirmed" || outcome == "busy" || outcome == "rejected" || outcome == "withdrawn" {
				require.NoError(t, err)
				require.True(t, r.Matches(c))
				require.Equal(t, outcome, r.Status)
			} else {
				require.Error(t, err)
				require.Nil(t, r)
				require.NotContains(t, err.Error(), "owned installer")
			}
			// Neither publisher can broaden its accepted command family accidentally.
			_, err = h.PublishNetbirdOperation(t.Context(), c)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationInvalid)
			// A response timeout does not join the broker callback. Keep its
			// original command immutable while checking a different family.
			connection := c
			connection.Version = 1
			connection.Operation = "up"
			connection.Package = packageapi.Package{}
			connection.ManagementURL = "https://owned.example.test"
			connection.ExpiresAt = at.Add(time.Minute)
			require.True(t, connection.Valid())
			_, err = h.PublishNetbirdInstallation(t.Context(), connection)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationInvalid)
		})
	}
	require.EqualValues(t, 10, calls.Load())
	stream, err := js.Stream(t.Context(), "AGENTS_STREAM")
	require.NoError(t, err)
	info, err := stream.Info(t.Context())
	require.NoError(t, err)
	require.Zero(t, info.State.Msgs)
}
