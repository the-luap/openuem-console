package webserver

import (
	"context"
	"testing"
	"time"
)

func TestCloseCancelsAndJoinsInventoryWorkerWithoutListener(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	w := &WebServer{inventoryCancel: cancel, inventoryDone: done}
	closed := make(chan error, 1)
	go func() { closed <- w.Close() }()
	select {
	case <-ctx.Done():
	case err := <-closed:
		close(done)
		t.Fatalf("Close returned without cancelling inventory dispatch: %v", err)
	case <-time.After(time.Second):
		close(done)
		t.Fatal("Close did not cancel inventory dispatch")
	}
	select {
	case err := <-closed:
		close(done)
		t.Fatalf("Close returned before inventory dispatch finished: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(done)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join the finished inventory worker")
	}
	if err := w.Close(); err != nil {
		t.Fatal("repeated shutdown failed", err)
	}
}
