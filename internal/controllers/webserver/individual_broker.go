package webserver

import (
	"errors"
	"net/http"
)

// serveWithBroker joins the HTTP serving goroutine when a permanent broker
// failure ends this listener. Temporary broker outages reconnect in place.
func serveWithBroker(server *http.Server, failure <-chan struct{}, serve func() error) error {
	if failure == nil {
		return serve()
	}
	select {
	case <-failure:
		return errors.New("individual console broker permissions or messaging failed")
	default:
	}
	stopped := make(chan error, 1)
	go func() { stopped <- serve() }()
	select {
	case err := <-stopped:
		return err
	case <-failure:
		_ = server.Close()
		<-stopped
		return errors.New("individual console broker permissions or messaging failed")
	}
}
