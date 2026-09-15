// Package consolebroker owns the console's private individual-agent connection.
package consolebroker

import (
	"errors"
	"log"
	"os"
	"sync"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	openuem "github.com/open-uem/nats"
)

// FromEnvironment selects one connection mode before legacy configuration is
// read. Missing or invalid individual settings never select legacy credentials.
func FromEnvironment() (*openuem.ServiceConnection, error) {
	switch os.Getenv("OPENUEM_INDIVIDUAL_AGENT_MODE") {
	case "", "false":
		return nil, nil
	case "true":
	default:
		return nil, errors.New("OPENUEM_INDIVIDUAL_AGENT_MODE must be true or false")
	}
	config := &openuem.ServiceConnection{
		Servers:         os.Getenv("OPENUEM_AGENT_BROKER_URLS"),
		KeyFile:         os.Getenv("OPENUEM_AGENT_CONSOLE_KEY_FILE"),
		CAFile:          os.Getenv("OPENUEM_AGENT_BROKER_CA_FILE"),
		CertificateFile: os.Getenv("OPENUEM_AGENT_BROKER_CLIENT_CERT_FILE"),
		TLSKeyFile:      os.Getenv("OPENUEM_AGENT_BROKER_CLIENT_KEY_FILE"),
	}
	if err := validate(*config); err != nil {
		return nil, err
	}
	return config, nil
}

func validate(config openuem.ServiceConnection) error {
	if !openuem.ValidServiceURLs(config.Servers) || config.KeyFile == "" || config.CAFile == "" {
		return errors.New("individual console requires explicit TLS broker URLs, a protected console NKey file and broker CA file")
	}
	if (config.CertificateFile == "") != (config.TLSKeyFile == "") {
		return errors.New("individual console broker client TLS requires both certificate and key files")
	}
	return nil
}

type Broker struct {
	Connection *nats.Conn
	JetStream  jetstream.JetStream
	failure    chan struct{}
	closed     chan struct{}
	closeOnce  sync.Once
}

// Connect creates a command publisher, without stream, consumer or election
// management. Those operations belong to the separate provisioner service.
func Connect(config openuem.ServiceConnection) (*Broker, error) {
	if err := validate(config); err != nil {
		return nil, err
	}
	b := &Broker{failure: make(chan struct{}), closed: make(chan struct{})}
	var failed, closed sync.Once
	fail := func() { failed.Do(func() { close(b.failure) }) }
	config.Name = "openuem-individual-console"
	config.ErrorHandler = func(*nats.Conn, *nats.Subscription, error) { fail() }
	config.Event = func(state string) {
		log.Printf("[INFO]: individual console broker %s", state)
		if state == "closed" {
			fail()
			closed.Do(func() { close(b.closed) })
		}
	}
	connection, err := openuem.ConnectService(config)
	if err != nil {
		return nil, err
	}
	b.Connection = connection
	b.JetStream, err = jetstream.New(connection)
	if err != nil {
		b.Close()
		return nil, errors.New("individual console command publisher is unavailable")
	}
	return b, nil
}

// Failure is closed for terminal closure or asynchronous permission errors.
// Temporary disconnects keep reconnecting to the explicitly configured brokers.
func (b *Broker) Failure() <-chan struct{} { return b.failure }

// Close joins the library's closed callback, including its NKey seed cleanup.
func (b *Broker) Close() {
	b.closeOnce.Do(func() {
		b.Connection.Close()
		<-b.closed
	})
}
