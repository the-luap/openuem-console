package handlers

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/taskexecution"
	"github.com/stretchr/testify/require"
)

func TestManualPublisherDirectAcceptanceRejectionAndTimeout(t *testing.T) {
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	require.NoError(t, err)
	broker.Start()
	defer func() { broker.Shutdown(); broker.WaitForShutdown() }()
	require.True(t, broker.ReadyForConnections(5*time.Second))
	nc, err := nats.Connect(broker.ClientURL())
	require.NoError(t, err)
	defer nc.Close()
	js, err := jetstream.New(nc)
	require.NoError(t, err)
	// Use the deployed stream configuration as well as the direct subscribers.
	// Core requests must not be captured, acknowledged or replayed by the stream.
	require.NoError(t, openuem.EnsureAgentCommandStream(t.Context(), js))
	h := &Handler{}
	h.setInventoryPublisher(js)
	id, request := uuid.NewString(), uuid.NewString()
	var deliveries atomic.Int32
	for _, operation := range []string{"ansible", "windowstask", "runprofile"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			messages := make(chan *nats.Msg, 2)
			sub, err := nc.Subscribe("agent."+operation+"."+id, func(msg *nats.Msg) {
				deliveries.Add(1)
				messages <- msg
				if string(msg.Data) == "accept" {
					_ = msg.Respond(nil)
				}
				if string(msg.Data) == "reject" {
					_ = msg.Respond([]byte("private agent configuration error"))
				}
			})
			require.NoError(t, err)
			defer sub.Unsubscribe()
			require.NoError(t, nc.FlushWithContext(ctx))
			payload := &taskexecution.Payload{Operation: operation, Data: []byte("accept")}
			require.NoError(t, h.PublishManualExecution(ctx, id, request, payload))
			msg := <-messages
			require.Equal(t, "agent."+operation+"."+id, msg.Subject)
			require.Equal(t, payload.Data, msg.Data)
			require.Empty(t, msg.Header.Get("Nats-Msg-Id"), "changing commands must not use stream redelivery")
			payload.Data = []byte("reject")
			err = h.PublishManualExecution(ctx, id, uuid.NewString(), payload)
			require.ErrorIs(t, err, inventory.ErrManualRejected)
			require.NotContains(t, err.Error(), "private")
			<-messages
			bounded, stop := context.WithTimeout(ctx, 80*time.Millisecond)
			payload.Data = []byte("withhold")
			err = h.PublishManualExecution(bounded, id, uuid.NewString(), payload)
			stop()
			require.ErrorIs(t, err, context.DeadlineExceeded)
			<-messages
		})
	}
	require.EqualValues(t, 9, deliveries.Load())
	stream, err := js.Stream(t.Context(), "AGENTS_STREAM")
	require.NoError(t, err)
	state, err := stream.Info(t.Context())
	require.NoError(t, err)
	require.Zero(t, state.State.Msgs)
	before := deliveries.Load()
	for _, payload := range []*taskexecution.Payload{nil, {Operation: "windowstask"}, {Operation: "windowstask", Data: make([]byte, taskexecution.MaxPayloadSize+1)}, {Operation: ">", Data: []byte("invalid")}, {Operation: "report", Data: []byte("invalid")}} {
		require.Error(t, h.PublishManualExecution(t.Context(), id, request, payload))
	}
	valid := &taskexecution.Payload{Operation: "windowstask", Data: []byte("accept")}
	for _, device := range []string{id + ".other", "*", id + "\n", strings.Repeat("a", 256)} {
		require.ErrorIs(t, h.PublishManualExecution(t.Context(), device, request, valid), inventory.ErrManualInvalid)
	}
	for _, value := range []string{"not-a-request", uuid.Nil.String(), strings.ToUpper(request)} {
		require.ErrorIs(t, h.PublishManualExecution(t.Context(), id, value, valid), inventory.ErrManualInvalid)
	}
	require.Equal(t, before, deliveries.Load())
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, h.PublishManualExecution(cancelled, id, request, valid), context.Canceled)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.True(t, errors.Is(h.PublishManualExecution(ctx, uuid.NewString(), request, valid), nats.ErrNoResponders))
	h.setInventoryPublisher(nil)
	require.ErrorIs(t, h.PublishManualExecution(ctx, id, request, valid), inventory.ErrRefreshNotReady)
}
