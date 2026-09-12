//go:build linux || windows

package common

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIndividualConsoleReleaseRequestCancellation(t *testing.T) {
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "openuem-console" {
			t.Error("release request changed its client identity")
		}
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	worker := &Worker{Context: ctx}
	done := make(chan error, 1)
	go func() { _, err := worker.queryReleasesEndpoint(server.URL); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("release request did not reach the controlled endpoint")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("release request did not preserve shutdown cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("release request ignored shutdown")
	}
}
