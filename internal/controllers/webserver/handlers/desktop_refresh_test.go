package handlers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/open-uem/openuem-console/internal/inventory"
)

func TestInventoryPublisherBindsSubjectStreamAndStableMessageID(t *testing.T) {
	s, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	defer func() { s.Shutdown(); s.WaitForShutdown() }()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("owned broker did not start")
	}
	nc, err := nats.Connect(s.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	stream, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "AGENTS_STREAM", Subjects: []string{"agent.report.*"}, Storage: jetstream.MemoryStorage})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{}
	h.setInventoryPublisher(js)
	id, request := uuid.NewString(), uuid.NewString()
	for range 2 {
		if err = h.PublishInventoryReport(ctx, id, request); err != nil {
			t.Fatal(err)
		}
	}
	info, err := stream.Info(ctx)
	if err != nil || info.State.Msgs != 1 {
		t.Fatal("broker did not deduplicate exact request", info, err)
	}
	message, err := stream.GetMsg(ctx, info.State.FirstSeq)
	if err != nil || message.Subject != "agent.report."+id || len(message.Data) != 0 || message.Header.Get("Nats-Msg-Id") != request {
		t.Fatal("command envelope changed", message, err)
	}
	for _, bad := range []string{"agent.*", id + ".other", id + "\n"} {
		if err = h.PublishInventoryReport(ctx, bad, request); !errors.Is(err, inventory.ErrRefreshInvalid) {
			t.Fatal("subject injection accepted", err)
		}
	}
	if err = h.PublishInventoryReport(ctx, id, "not-a-request"); !errors.Is(err, inventory.ErrRefreshInvalid) {
		t.Fatal("unbound request ID accepted", err)
	}
	if err = js.DeleteStream(ctx, "AGENTS_STREAM"); err != nil {
		t.Fatal(err)
	}
	if _, err = js.CreateStream(ctx, jetstream.StreamConfig{Name: "OTHER_STREAM", Subjects: []string{"agent.report.*"}, Storage: jetstream.MemoryStorage}); err != nil {
		t.Fatal(err)
	}
	if err = h.PublishInventoryReport(ctx, id, uuid.NewString()); err == nil {
		t.Fatal("unexpected stream accepted command")
	}
	h.setInventoryPublisher(nil)
	if err = h.PublishInventoryReport(ctx, id, uuid.NewString()); !errors.Is(err, inventory.ErrRefreshNotReady) {
		t.Fatal("missing publisher reported success", err)
	}
}
