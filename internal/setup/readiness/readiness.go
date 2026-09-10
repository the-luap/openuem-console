// Package readiness performs bounded, read-only reference deployment probes.
package readiness

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/keyfile"
)

var ErrConfiguration = errors.New("reference probe requires valid explicit protected configuration")
var ErrNotReady = errors.New("reference service did not become ready before the probe deadline")

type Options struct {
	Mode      string
	Address   string
	Origin    string
	TrustFile string
	KeyFile   string
}

// Wait checks the actual listener and retries only until the caller's deadline.
// Broker probes authenticate the retained worker and verify its subscription
// boundary; run them during maintenance before restarting public device traffic.
func Wait(ctx context.Context, options Options) error {
	if _, ok := ctx.Deadline(); !ok {
		return ErrConfiguration
	}
	var check func() bool
	var close func()
	var err error
	switch options.Mode {
	case "broker":
		check, close, err = brokerCheck(ctx, options)
	case "http":
		check, close, err = healthCheck(ctx, options)
	case "gateway":
		check, close, err = gatewayCheck(ctx, options)
	default:
		return ErrConfiguration
	}
	if err != nil {
		return err
	}
	defer close()
	for ctx.Err() == nil {
		if check() && ctx.Err() == nil {
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrNotReady
		case <-timer.C:
		}
	}
	return ErrNotReady
}

func protectedFile(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrConfiguration
	}
	file, err := keyfile.Open(path, limit)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		clear(data)
		return nil, ErrConfiguration
	}
	return data, nil
}

func brokerCheck(ctx context.Context, options Options) (func() bool, func(), error) {
	endpoint, err := url.Parse(options.Address)
	if err != nil || endpoint.Scheme != "tls" || endpoint.Hostname() == "" || endpoint.Port() == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || options.Origin != "" {
		return nil, nil, ErrConfiguration
	}
	seed, err := protectedFile(options.KeyFile, 512)
	if err != nil {
		return nil, nil, err
	}
	defer clear(seed)
	pair, err := nkeys.FromSeed(bytes.TrimSpace(seed))
	if err != nil {
		return nil, nil, ErrConfiguration
	}
	public, err := pair.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		pair.Wipe()
		return nil, nil, ErrConfiguration
	}
	trust, err := protectedFile(options.TrustFile, 64<<10)
	if err != nil {
		pair.Wipe()
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	valid := pool.AppendCertsFromPEM(trust)
	clear(trust)
	if !valid {
		pair.Wipe()
		return nil, nil, ErrConfiguration
	}
	check := func() bool {
		connection, err := nats.Connect(options.Address, nats.Nkey(public, pair.Sign), nats.Secure(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}), nats.NoReconnect(), nats.SetCustomDialer(contextDialer{ctx: ctx}), nats.Timeout(2*time.Second), nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) {}))
		if err != nil {
			return false
		}
		defer connection.Close()
		for _, operation := range enrollment.Operations() {
			if _, err := connection.SubscribeSync("uem.v1.agent.*.request." + operation); err != nil {
				return false
			}
		}
		if connection.FlushTimeout(2*time.Second) != nil || connection.LastError() != nil {
			return false
		}
		if _, err := connection.SubscribeSync("uem.v1.agent.*.request.>"); err != nil {
			return false
		}
		return connection.FlushTimeout(2*time.Second) == nil && errors.Is(connection.LastError(), nats.ErrPermissionViolation)
	}
	return check, pair.Wipe, nil
}

func healthCheck(ctx context.Context, options Options) (func() bool, func(), error) {
	endpoint, err := url.Parse(options.Address)
	if err != nil || endpoint.Scheme != "http" || endpoint.User != nil || endpoint.Path != "/healthz" || endpoint.RawQuery != "" || endpoint.Fragment != "" || options.Origin != "" || options.KeyFile != "" || options.TrustFile != "" {
		return nil, nil, ErrConfiguration
	}
	address := net.ParseIP(endpoint.Hostname())
	if address == nil || !address.IsLoopback() || endpoint.Port() == "" {
		return nil, nil, ErrConfiguration
	}
	transport := &http.Transport{Proxy: nil}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func() bool { return status(ctx, client, options.Address, http.StatusNoContent) }, transport.CloseIdleConnections, nil
}

func gatewayCheck(ctx context.Context, options Options) (func() bool, func(), error) {
	origin, err := url.Parse(options.Origin)
	address, port, splitErr := net.SplitHostPort(options.Address)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.Opaque != "" || strings.HasSuffix(options.Origin, "/") || splitErr != nil || net.ParseIP(address) == nil || port == "" || options.KeyFile != "" {
		return nil, nil, ErrConfiguration
	}
	data, err := protectedFile(options.TrustFile, 64<<10)
	if err != nil {
		return nil, nil, err
	}
	defer clear(data)
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, ErrConfiguration
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, ErrConfiguration
	}
	// Pin the actual locally provisioned gateway leaf, independently of whether
	// production uses public ACME trust or the isolated fixture's synthetic CA.
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: origin.Hostname(), VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, certificate.Raw) {
			return ErrNotReady
		}
		return nil
	}}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, options.Address)
	}}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func() bool {
		for _, path := range []string{"/EnrollmentServer/Discovery.svc", "/enroll/desktop/bootstrap-keys"} {
			if !status(ctx, client, options.Origin+path, http.StatusOK) {
				return false
			}
		}
		return true
	}, transport.CloseIdleConnections, nil
}

func status(ctx context.Context, client *http.Client, address string, expected int) bool {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	return err == nil && response.StatusCode == expected
}

// Closing the underlying connection on cancellation also interrupts the NATS
// TLS handshake and flush waits, not just the initial TCP dial.
type contextDialer struct{ ctx context.Context }

func (dialer contextDialer) Dial(network, address string) (net.Conn, error) {
	connection, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(dialer.ctx, network, address)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(dialer.ctx, func() { _ = connection.Close() })
	return &contextConnection{Conn: connection, stop: stop}, nil
}

type contextConnection struct {
	net.Conn
	stop func() bool
}

func (connection *contextConnection) Close() error { connection.stop(); return connection.Conn.Close() }
