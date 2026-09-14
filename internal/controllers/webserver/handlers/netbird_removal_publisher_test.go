package handlers

import (
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

func TestNetbirdRemovalCannotUseConnectionOrInstallationPublisher(t *testing.T) {
	h, nc, js := netbirdPublisherFixture(t)
	at := time.Now().UTC()
	c := netbirdcommand.Command{Version: netbirdcommand.RemovalVersion, Identity: netbirdcommand.Identity{DeviceID: uuid.NewString(), TenantID: 3, SiteID: 4, Individual: true, CertificateHash: strings.Repeat("a", 64)}, RequestID: uuid.NewString(), Revision: strings.Repeat("b", 64), Operation: "uninstall", IssuedAt: at, ExpiresAt: at.Add(netbirdcommand.RemovalLifetime), Removal: packageapi.Removal{Schema: 1, Platform: "macos", Architecture: "arm64", Format: "pkg", PackageID: "io.netbird.client", Version: "0.78.1", StateDigest: strings.Repeat("c", 64)}}
	require.True(t, c.Valid())
	var calls atomic.Int32
	subject, err := netbirdcommand.Subject(c.DeviceID)
	require.NoError(t, err)
	sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
		calls.Add(1)
		r, _ := netbirdcommand.ReceiptFor(c, "completed")
		body, _ := netbirdcommand.EncodeReceipt(r)
		_ = msg.Respond(body)
	})
	require.NoError(t, err)
	defer sub.Unsubscribe()
	require.NoError(t, nc.Flush())
	_, err = h.PublishNetbirdOperation(t.Context(), c)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationInvalid)
	_, err = h.PublishNetbirdInstallation(t.Context(), c)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationInvalid)
	require.Zero(t, calls.Load())
	stream, err := js.Stream(t.Context(), "AGENTS_STREAM")
	require.NoError(t, err)
	info, err := stream.Info(t.Context())
	require.NoError(t, err)
	require.Zero(t, info.State.Msgs)
}

func TestNetbirdRemovalInspectionPublisherRetainsExactNativeEvidence(t *testing.T) {
	h, nc, _ := netbirdPublisherFixture(t)
	for _, outcome := range []string{"ok", "absent", "unavailable", "wrong-hash", "wrong-certificate", "old-version"} {
		t.Run(outcome, func(t *testing.T) {
			at := time.Now().UTC()
			c := netbirdcommand.ControlRequest{Version: netbirdcommand.RemovalInspectionVersion, Identity: netbirdcommand.Identity{DeviceID: uuid.NewString(), TenantID: 3, SiteID: 4, Individual: true, CertificateHash: strings.Repeat("a", 64)}, RequestID: uuid.NewString(), Kind: "removal-state", IssuedAt: at, ExpiresAt: at.Add(netbirdcommand.RemovalInspectionLifetime)}
			subject, err := netbirdcommand.ControlSubject(c.DeviceID)
			require.NoError(t, err)
			var calls atomic.Int32
			sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
				calls.Add(1)
				decoded, err := netbirdcommand.DecodeControl(msg.Data)
				if err != nil || decoded != c {
					_ = msg.Respond(nil)
					return
				}
				r, _ := netbirdcommand.ControlResponseFor(c, "ok")
				r.State = netbirdcommand.State{Status: "ready", Revision: strings.Repeat("e", 64), Remaining: 100}
				r.Removal = packageapi.Removal{Schema: 1, Platform: "macos", Architecture: "arm64", Format: "pkg", PackageID: "io.netbird.client", Version: "0.78.1", StateDigest: strings.Repeat("f", 64)}
				if outcome == "absent" {
					r.Outcome = outcome
					r.Removal = packageapi.Removal{}
				}
				if outcome == "unavailable" {
					r.Outcome = outcome
					r.State = netbirdcommand.State{}
					r.Removal = packageapi.Removal{}
				}
				data, _ := netbirdcommand.EncodeControlResponse(c, r)
				switch outcome {
				case "wrong-hash":
					data = []byte(strings.Replace(string(data), r.RequestHash, strings.Repeat("0", 64), 1))
				case "wrong-certificate":
					data = []byte(strings.Replace(string(data), c.CertificateHash, strings.Repeat("0", 64), 1))
				case "old-version":
					data = []byte(strings.Replace(string(data), `"version":3`, `"version":1`, 1))
				}
				_ = msg.Respond(data)
			})
			require.NoError(t, err)
			defer sub.Unsubscribe()
			require.NoError(t, nc.Flush())
			r, err := h.RequestNetbirdControl(t.Context(), c)
			if outcome == "ok" || outcome == "absent" || outcome == "unavailable" {
				require.NoError(t, err)
				require.Equal(t, outcome, r.Outcome)
				require.True(t, r.Matches(c))
			} else {
				require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
				require.Nil(t, r)
			}
			require.EqualValues(t, 1, calls.Load())
		})
	}
}
