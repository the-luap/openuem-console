package handlers

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/stretchr/testify/require"
)

func netbirdPublisherFixture(t *testing.T) (*Handler, *nats.Conn, jetstream.JetStream) {
	t.Helper()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	require.NoError(t, err)
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	require.True(t, broker.ReadyForConnections(5*time.Second))
	nc, err := nats.Connect(broker.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	require.NoError(t, err)
	require.NoError(t, openuem.EnsureAgentCommandStream(t.Context(), js))
	h := &Handler{}
	h.setInventoryPublisher(js)
	return h, nc, js
}

func TestNetbirdPublisherCorrelatedReceiptAndSingleDelivery(t *testing.T) {
	h, nc, js := netbirdPublisherFixture(t)
	var calls atomic.Int32
	for _, outcome := range []string{"completed", "unconfirmed", "busy", "rejected", "empty", "wrong-hash", "wrong-request", "malformed", "withhold"} {
		t.Run(outcome, func(t *testing.T) {
			now := time.Now().UTC()
			c := netbirdcommand.Command{Version: 1, Identity: netbirdcommand.Identity{DeviceID: uuid.NewString(), TenantID: 3, SiteID: 4}, RequestID: uuid.NewString(), Revision: strings.Repeat("a", 64), Operation: "up", ManagementURL: "https://owned.example.test", IssuedAt: now, ExpiresAt: now.Add(time.Second)}
			subject, _ := netbirdcommand.Subject(c.DeviceID)
			sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
				calls.Add(1)
				decoded, err := netbirdcommand.Decode(msg.Data)
				if err != nil || decoded != c {
					_ = msg.Respond([]byte("invalid command"))
					return
				}
				r, _ := netbirdcommand.ReceiptFor(c, "completed")
				switch outcome {
				case "completed", "unconfirmed", "busy", "rejected":
					r.Status = outcome
				case "empty":
					_ = msg.Respond(nil)
					return
				case "malformed":
					_ = msg.Respond([]byte(`{"private":"agent output"}`))
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
			result, err := h.PublishNetbirdOperation(ctx, c)
			if outcome == "completed" {
				require.NoError(t, err)
				require.True(t, result.Success)
				hash, _ := c.Digest()
				require.Equal(t, hash, result.CommandHash)
			} else {
				require.Error(t, err)
				require.Nil(t, result)
				require.NotContains(t, err.Error(), "agent output")
			}
			c.ExpiresAt = c.IssuedAt
			c.IssuedAt = c.IssuedAt.Add(-time.Second)
			_, err = h.PublishNetbirdOperation(t.Context(), c)
			require.Error(t, err)
		})
	}
	require.EqualValues(t, 9, calls.Load())
	stream, err := js.Stream(t.Context(), "AGENTS_STREAM")
	require.NoError(t, err)
	info, err := stream.Info(t.Context())
	require.NoError(t, err)
	require.Zero(t, info.State.Msgs)
}

func TestNetbirdPublisherLiveControlRejectsUnrelatedEvidence(t *testing.T) {
	h, nc, js := netbirdPublisherFixture(t)
	identity := netbirdcommand.Identity{DeviceID: uuid.NewString(), TenantID: 3, SiteID: 4, Individual: true, CertificateHash: strings.Repeat("a", 64)}
	subject, _ := netbirdcommand.ControlSubject(identity.DeviceID)
	var requests atomic.Int32
	var wrong atomic.Bool
	sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
		requests.Add(1)
		c, err := netbirdcommand.DecodeControl(msg.Data)
		if err != nil {
			_ = msg.Respond(nil)
			return
		}
		r, _ := netbirdcommand.ControlResponseFor(c, "ok")
		r.State = netbirdcommand.State{Status: "ready", Revision: strings.Repeat("b", 64), Remaining: 4096}
		if wrong.Load() {
			c.RequestID = uuid.NewString()
			r, _ = netbirdcommand.ControlResponseFor(c, "unavailable")
		}
		data, _ := netbirdcommand.EncodeControlResponse(c, r)
		_ = msg.Respond(data)
	})
	require.NoError(t, err)
	defer sub.Unsubscribe()
	require.NoError(t, nc.Flush())
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	state, err := h.InspectNetbirdJournal(ctx, identity)
	require.NoError(t, err)
	require.Equal(t, "ready", state.Status)
	wrong.Store(true)
	_, err = h.InspectNetbirdJournal(ctx, identity)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	cancelled, stop := context.WithCancel(t.Context())
	stop()
	_, err = h.InspectNetbirdJournal(cancelled, identity)
	require.ErrorIs(t, err, context.Canceled)
	old := identity
	old.DeviceID = uuid.NewString()
	_, err = h.InspectNetbirdJournal(ctx, old)
	require.ErrorIs(t, err, nats.ErrNoResponders)
	require.EqualValues(t, 2, requests.Load())
	h.setInventoryPublisher(nil)
	_, err = h.InspectNetbirdJournal(ctx, identity)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationNotReady)
	stream, err := js.Stream(t.Context(), "AGENTS_STREAM")
	require.NoError(t, err)
	info, err := stream.Info(t.Context())
	require.NoError(t, err)
	require.Zero(t, info.State.Msgs)
}
