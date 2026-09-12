package webserver

import (
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/controllers/webserver/handlers"
)

func TestIndividualBrokerFailureJoinsHTTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.NotFoundHandler()}
	defer server.Close()
	failure := make(chan struct{})
	served := make(chan struct{})
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- serveWithBroker(server, failure, func() error { close(started); defer close(served); return server.Serve(listener) })
	}()
	<-started
	close(failure)
	select {
	case err := <-result:
		if err == nil || err.Error() != "individual console broker permissions or messaging failed" {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP serving survived broker failure")
	}
	select {
	case <-served:
	default:
		t.Fatal("serving goroutine was not joined")
	}
	if err := serveWithBroker(server, failure, func() error { t.Fatal("failed broker admitted HTTP startup"); return nil }); err == nil {
		t.Fatal("closed failure channel accepted")
	}
}

func TestIndividualBrokerHTTPStopReturnsOriginalError(t *testing.T) {
	expected := errors.New("listener setup failed")
	for _, failure := range []<-chan struct{}{nil, make(chan struct{})} {
		if err := serveWithBroker(&http.Server{}, failure, func() error { return expected }); err != expected {
			t.Fatal("HTTP error changed", err)
		}
	}
}

func TestIndividualBrokerRequiredBeforeServing(t *testing.T) {
	w := &WebServer{Handler: &handlers.Handler{IndividualAgentService: &openuem.ServiceConnection{}}}
	if err := w.Serve("127.0.0.1:0", "missing.pem", "missing.key"); err == nil || err.Error() != "individual console broker must be connected before serving" {
		t.Fatal("unconnected individual mode reached database or HTTP startup", err)
	}
}
