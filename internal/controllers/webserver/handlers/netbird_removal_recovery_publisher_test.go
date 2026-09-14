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

func recoveryPublisherCommand() netbirdcommand.Command {
	at := time.Now().UTC()
	original := netbirdcommand.RemovalRecoveryReference{RequestID: uuid.NewString(), CommandHash: strings.Repeat("c", 64), Revision: strings.Repeat("d", 64), ReleaseID: uuid.NewString(), Removal: packageapi.Removal{Schema: 1, Platform: "macos", Architecture: "arm64", Format: "pkg", PackageID: "io.netbird.client", Version: "0.78.1", StateDigest: strings.Repeat("e", 64)}}
	return netbirdcommand.Command{Version: netbirdcommand.RemovalRecoveryVersion, Identity: netbirdcommand.Identity{DeviceID: uuid.NewString(), TenantID: 3, SiteID: 4, Individual: true, CertificateHash: strings.Repeat("a", 64)}, RequestID: uuid.NewString(), Revision: strings.Repeat("b", 64), Operation: "recover-removal", IssuedAt: at, ExpiresAt: at.Add(netbirdcommand.RemovalRecoveryLifetime), RemovalRecovery: netbirdcommand.RemovalRecovery{Original: original, Mode: "manifest", JournalRevision: strings.Repeat("f", 64), StateDigest: strings.Repeat("0", 64)}}
}

func TestNetbirdRecoveryPublisherUsesOneSeparateDirectAttempt(t *testing.T) {
	h, nc, js := netbirdPublisherFixture(t)
	for _, outcome := range []string{"completed", "unconfirmed", "busy", "rejected", "withdrawn", "wrong-original", "wrong-release", "wrong-journal", "wrong-current-state", "wrong-operation", "no-reply", "cancelled", "expired", "original-id", "legacy"} {
		t.Run(outcome, func(t *testing.T) {
			c := recoveryPublisherCommand()
			var calls atomic.Int32
			subject, _ := netbirdcommand.Subject(c.DeviceID)
			sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
				calls.Add(1)
				decoded, err := netbirdcommand.Decode(msg.Data)
				if err != nil || decoded != c {
					t.Error("recovery envelope changed")
					_ = msg.Respond(nil)
					return
				}
				if outcome == "no-reply" {
					return
				}
				other := c
				switch outcome {
				case "wrong-original":
					other.RemovalRecovery.Original.CommandHash = strings.Repeat("1", 64)
				case "wrong-release":
					other.RemovalRecovery.Original.ReleaseID = uuid.NewString()
				case "wrong-journal":
					other.RemovalRecovery.JournalRevision = strings.Repeat("1", 64)
				case "wrong-current-state":
					other.RemovalRecovery.StateDigest = strings.Repeat("1", 64)
				}
				status := outcome
				if strings.HasPrefix(outcome, "wrong-") {
					status = "completed"
				}
				r, err := netbirdcommand.ReceiptFor(other, status)
				if err != nil {
					t.Error(err)
					_ = msg.Respond(nil)
					return
				}
				if outcome == "wrong-operation" {
					r.Operation = "uninstall"
				}
				body, _ := netbirdcommand.EncodeReceipt(r)
				_ = msg.Respond(body)
			})
			require.NoError(t, err)
			defer sub.Unsubscribe()
			require.NoError(t, nc.Flush())
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			switch outcome {
			case "cancelled":
				cancel()
			case "expired":
				c.IssuedAt = c.IssuedAt.Add(-time.Hour)
				c.ExpiresAt = c.ExpiresAt.Add(-time.Hour)
			case "original-id":
				c.RequestID = c.RemovalRecovery.Original.RequestID
			case "legacy":
				c.Individual = false
				c.CertificateHash = ""
			}
			r, err := h.PublishNetbirdRemovalRecovery(ctx, c)
			switch {
			case strings.HasPrefix(outcome, "wrong-"):
				require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
				require.Nil(t, r)
				require.EqualValues(t, 1, calls.Load())
			case outcome == "no-reply" || outcome == "cancelled":
				require.ErrorIs(t, err, inventory.ErrNetbirdOperationNotReady)
				require.Nil(t, r)
				if outcome == "no-reply" {
					require.EqualValues(t, 1, calls.Load())
				} else {
					require.Zero(t, calls.Load())
				}
			case outcome == "expired" || outcome == "original-id" || outcome == "legacy":
				require.ErrorIs(t, err, inventory.ErrNetbirdOperationInvalid)
				require.Nil(t, r)
				require.Zero(t, calls.Load())
			default:
				require.NoError(t, err)
				require.True(t, r.Matches(c))
				require.Equal(t, outcome, r.Status)
				require.EqualValues(t, 1, calls.Load())
			}
		})
	}
	c := recoveryPublisherCommand()
	_, err := h.PublishNetbirdOperation(t.Context(), c)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationInvalid)
	for _, publish := range []func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error){h.PublishNetbirdInstallation, h.PublishNetbirdRemoval} {
		r, err := publish(t.Context(), c)
		require.ErrorIs(t, err, inventory.ErrNetbirdOperationInvalid)
		require.Nil(t, r)
	}
	original := c
	original.Version = netbirdcommand.RemovalVersion
	original.Operation = "uninstall"
	original.RequestID = c.RemovalRecovery.Original.RequestID
	original.Removal = c.RemovalRecovery.Original.Removal
	original.RemovalRecovery = netbirdcommand.RemovalRecovery{}
	require.True(t, original.Valid())
	r, err := h.PublishNetbirdRemovalRecovery(t.Context(), original)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationInvalid)
	require.Nil(t, r)
	stream, err := js.Stream(t.Context(), "AGENTS_STREAM")
	require.NoError(t, err)
	info, err := stream.Info(t.Context())
	require.NoError(t, err)
	require.Zero(t, info.State.Msgs)
}

func TestNetbirdRecoveryControlPublisherRequiresExactCurrentEvidence(t *testing.T) {
	h, nc, _ := netbirdPublisherFixture(t)
	for _, outcome := range []string{"ok", "missing", "blocked", "conflict", "unavailable", "wrong-original", "wrong-release", "wrong-journal", "wrong-hash", "wrong-certificate", "old-version"} {
		t.Run(outcome, func(t *testing.T) {
			command := recoveryPublisherCommand()
			c := netbirdcommand.ControlRequest{Version: netbirdcommand.RemovalRecoveryInspectionVersion, Identity: command.Identity, RequestID: uuid.NewString(), Kind: "removal-recovery-state", RemovalRecoveryOriginal: command.RemovalRecovery.Original, IssuedAt: command.IssuedAt, ExpiresAt: command.IssuedAt.Add(netbirdcommand.RemovalRecoveryInspectionLifetime)}
			subject, _ := netbirdcommand.ControlSubject(c.DeviceID)
			var calls atomic.Int32
			sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
				calls.Add(1)
				got, err := netbirdcommand.DecodeControl(msg.Data)
				if err != nil || got != c {
					t.Error("inspection changed reference")
					_ = msg.Respond(nil)
					return
				}
				status := outcome
				if strings.HasPrefix(status, "wrong-") || status == "old-version" {
					status = "ok"
				}
				r, _ := netbirdcommand.ControlResponseFor(c, status)
				if status == "ok" {
					r.State = netbirdcommand.State{Status: "ready", Revision: command.RemovalRecovery.JournalRevision, Remaining: 100}
					r.RemovalRecovery = command.RemovalRecovery
				}
				data, err := netbirdcommand.EncodeControlResponse(c, r)
				if err != nil {
					t.Error(err)
					_ = msg.Respond(nil)
					return
				}
				switch outcome {
				case "wrong-original":
					data = []byte(strings.Replace(string(data), command.RemovalRecovery.Original.CommandHash, strings.Repeat("1", 64), 1))
				case "wrong-release":
					data = []byte(strings.Replace(string(data), command.RemovalRecovery.Original.ReleaseID, uuid.NewString(), 1))
				case "wrong-journal":
					data = []byte(strings.Replace(string(data), `"journal_revision":"`+command.RemovalRecovery.JournalRevision, `"journal_revision":"`+strings.Repeat("1", 64), 1))
				case "wrong-hash":
					data = []byte(strings.Replace(string(data), r.RequestHash, strings.Repeat("1", 64), 1))
				case "wrong-certificate":
					data = []byte(strings.Replace(string(data), c.CertificateHash, strings.Repeat("1", 64), 1))
				case "old-version":
					data = []byte(strings.Replace(string(data), `"version":4`, `"version":3`, 1))
				}
				_ = msg.Respond(data)
			})
			require.NoError(t, err)
			defer sub.Unsubscribe()
			require.NoError(t, nc.Flush())
			r, err := h.RequestNetbirdControl(t.Context(), c)
			if strings.HasPrefix(outcome, "wrong-") || outcome == "old-version" {
				require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
				require.Nil(t, r)
			} else {
				require.NoError(t, err)
				require.True(t, r.Matches(c))
				require.Equal(t, outcome, r.Outcome)
			}
			require.EqualValues(t, 1, calls.Load())
		})
	}
}
