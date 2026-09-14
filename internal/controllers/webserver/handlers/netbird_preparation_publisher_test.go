package handlers

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/stretchr/testify/require"
)

func TestNetbirdPublisherPreparationRequiresExactPrivateResponseAndNeverStreams(t *testing.T) {
	h, nc, js := netbirdPublisherFixture(t)
	var calls atomic.Int32
	for _, outcome := range []string{"prepared", "blocked", "conflict", "unavailable", "empty", "wrong-hash", "wrong-identity", "wrong-request", "malformed", "withhold"} {
		t.Run(outcome, func(t *testing.T) {
			now := time.Now().UTC()
			p := netbirdcommand.PreparationRequest{Version: 1, Identity: netbirdcommand.Identity{DeviceID: uuid.NewString(), TenantID: 3, SiteID: 4, Individual: true, CertificateHash: strings.Repeat("a", 64)}, RequestID: uuid.NewString(), Revision: strings.Repeat("b", 64), JournalRevision: strings.Repeat("c", 64), Package: packageapi.Package{Schema: 1, ApprovalID: uuid.NewString(), TenantID: 3, Platform: "macos", Architecture: "arm64", Format: "pkg", PackageID: "io.netbird.client", Version: "0.78.1", URL: "https://packages.example.test/netbird.pkg?private=owned-source", Size: 100, SHA256: strings.Repeat("d", 64)}, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
			require.True(t, p.Valid())
			subject, err := netbirdcommand.PreparationSubject(p.DeviceID)
			require.NoError(t, err)
			sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
				calls.Add(1)
				decoded, err := netbirdcommand.DecodePreparation(msg.Data)
				if err != nil || decoded != p {
					_ = msg.Respond(nil)
					return
				}
				r, _ := netbirdcommand.PreparationResponseFor(p, "prepared")
				switch outcome {
				case "blocked", "conflict", "unavailable":
					r.Outcome = outcome
				case "empty":
					_ = msg.Respond(nil)
					return
				case "malformed":
					_ = msg.Respond([]byte(`{"private":"owned source diagnostic"}`))
					return
				case "withhold":
					return
				case "wrong-hash":
					r.RequestHash = strings.Repeat("f", 64)
				case "wrong-identity":
					r.CertificateHash = strings.Repeat("f", 64)
				case "wrong-request":
					r.RequestID = uuid.NewString()
				}
				data, _ := json.Marshal(r)
				_ = msg.Respond(data)
			})
			require.NoError(t, err)
			defer sub.Unsubscribe()
			require.NoError(t, nc.Flush())
			ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
			defer cancel()
			got, err := h.PublishNetbirdPreparation(ctx, p)
			if outcome == "prepared" || outcome == "blocked" || outcome == "conflict" || outcome == "unavailable" {
				require.NoError(t, err)
				require.True(t, got.Matches(p))
				require.Equal(t, outcome, got.Outcome)
			} else {
				require.Error(t, err)
				require.Nil(t, got)
				require.NotContains(t, err.Error(), "owned source")
			}
			p.ExpiresAt = p.IssuedAt
			p.IssuedAt = p.IssuedAt.Add(-time.Minute)
			_, err = h.PublishNetbirdPreparation(t.Context(), p)
			require.Error(t, err)
		})
	}
	require.EqualValues(t, 10, calls.Load())
	stream, err := js.Stream(t.Context(), "AGENTS_STREAM")
	require.NoError(t, err)
	info, err := stream.Info(t.Context())
	require.NoError(t, err)
	require.Zero(t, info.State.Msgs)
}
