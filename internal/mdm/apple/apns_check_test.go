package apple

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

type apnsTLSFixture struct {
	client, server           tls.Certificate
	serverRoots, clientRoots *x509.CertPool
}

func newAPNsTLSFixture(t *testing.T, hostname string) apnsTLSFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(40), Subject: pkix.Name{CommonName: "Loopback APNs server CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootPEM := signPushLeaf(t, rootTemplate, rootTemplate, &key.PublicKey, key)
	block, _ := pem.Decode(rootPEM)
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(41), DNSNames: []string{hostname}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverPEM := signPushLeaf(t, serverTemplate, root, &key.PublicKey, key)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	server, err := tls.X509KeyPair(serverPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	clientRoot, clientSigner := testPushCA(t)
	clientPEM := signPushLeaf(t, pushLeafTemplate(), clientRoot, &key.PublicKey, clientSigner)
	client, err := tls.X509KeyPair(clientPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	serverRoots, clientRoots := x509.NewCertPool(), x509.NewCertPool()
	serverRoots.AddCert(root)
	clientRoots.AddCert(clientRoot)
	return apnsTLSFixture{client, server, serverRoots, clientRoots}
}

func loopbackAPNsDialer(t *testing.T, address string) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	return func(ctx context.Context, network, host string) (net.Conn, error) {
		if network != "tcp" || host != "api.push.apple.com:443" {
			t.Error("probe changed the production endpoint", network, host)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > apnsCheckTimeout {
			t.Error("probe has no bounded deadline")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
}

func TestAPNsCheckFreshCertificateConnection(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			fixture := newAPNsTLSFixture(t, apnsProductionHost)
			var handshakes, requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
			server.EnableHTTP2 = true
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{Certificates: []tls.Certificate{fixture.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: fixture.clientRoots, MinVersion: version, MaxVersion: version, VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) != 1 || !bytes.Equal(state.PeerCertificates[0].Raw, fixture.client.Certificate[0]) || state.ServerName != apnsProductionHost {
					return errors.New("wrong candidate client credential or hostname")
				}
				handshakes.Add(1)
				return nil
			}}
			server.StartTLS()
			defer server.Close()
			for i := 0; i < 2; i++ {
				if err := probeAPNsConnection(t.Context(), fixture.client, loopbackAPNsDialer(t, server.Listener.Addr().String()), fixture.serverRoots); err != nil {
					t.Fatal(err)
				}
			}
			if handshakes.Load() != 2 || requests.Load() != 0 {
				t.Fatal("probe reused credentials or sent HTTP/device requests", handshakes.Load(), requests.Load())
			}
		})
	}
}

func TestAPNsCheckTLSFailures(t *testing.T) {
	for _, name := range []string{"wrong hostname", "untrusted server", "server did not request certificate", "server rejects client TLS12", "server rejects client TLS13", "no HTTP2", "old TLS"} {
		t.Run(name, func(t *testing.T) {
			hostname := apnsProductionHost
			if name == "wrong hostname" {
				hostname = "other.example.test"
			}
			fixture := newAPNsTLSFixture(t, hostname)
			roots := fixture.serverRoots
			if name == "untrusted server" {
				roots = fixture.clientRoots
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("connection check sent an HTTP request") }))
			server.EnableHTTP2 = true
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{Certificates: []tls.Certificate{fixture.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: fixture.clientRoots, MinVersion: tls.VersionTLS12}
			switch name {
			case "server did not request certificate":
				server.TLS.ClientAuth = tls.NoClientCert
			case "server rejects client TLS12", "server rejects client TLS13":
				server.TLS.VerifyConnection = func(tls.ConnectionState) error { return errors.New("rejected test credential") }
				if name == "server rejects client TLS12" {
					server.TLS.MaxVersion = tls.VersionTLS12
				} else {
					server.TLS.MinVersion = tls.VersionTLS13
				}
			case "no HTTP2":
				server.EnableHTTP2 = false
				server.TLS.NextProtos = []string{"http/1.1"}
			case "old TLS":
				server.TLS.MinVersion = tls.VersionTLS11
				server.TLS.MaxVersion = tls.VersionTLS11
			}
			server.StartTLS()
			defer server.Close()
			if err := probeAPNsConnection(t.Context(), fixture.client, loopbackAPNsDialer(t, server.Listener.Addr().String()), roots); !errors.Is(err, ErrPushConnection) {
				t.Fatal("invalid TLS peer accepted", err)
			}
		})
	}
}

func TestAPNsCheckCancellationAndDialFailure(t *testing.T) {
	fixture := newAPNsTLSFixture(t, apnsProductionHost)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := probeAPNsConnection(ctx, fixture.client, func(context.Context, string, string) (net.Conn, error) {
		t.Error("canceled check dialed")
		return nil, errors.New("unexpected dial")
	}, fixture.serverRoots); !errors.Is(err, ErrPushConnection) {
		t.Fatal(err)
	}
	if err := probeAPNsConnection(t.Context(), fixture.client, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("private dial error") }, fixture.serverRoots); err != ErrPushConnection {
		t.Fatal("dial error leaked", err)
	}
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- probeAPNsConnection(ctx, fixture.client, func(context.Context, string, string) (net.Conn, error) { close(started); return client, nil }, fixture.serverRoots)
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if err != ErrPushConnection {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stalled TLS check ignored cancellation")
	}
	if err := checkAPNsConnection(t.Context(), &Settings{PushCertificate: []byte("invalid")}); err != ErrPushConnection {
		t.Fatal("invalid credential accepted", err)
	}
}

func TestAPNsCheckRequiresHTTP2Acknowledgement(t *testing.T) {
	for _, mode := range []string{"ack", "wrong ack", "no ack", "goaway", "closed"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newAPNsTLSFixture(t, apnsProductionHost)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			var receivedPing atomic.Bool
			go func() {
				defer close(done)
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				defer connection.Close()
				connection.SetDeadline(time.Now().Add(3 * time.Second))
				secured := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{fixture.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: fixture.clientRoots, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
				if err := secured.Handshake(); err != nil {
					return
				}
				if mode == "closed" {
					return
				}
				preface := make([]byte, len(http2.ClientPreface))
				if _, err = io.ReadFull(secured, preface); err != nil {
					return
				}
				if string(preface) != http2.ClientPreface {
					t.Error("missing HTTP2 preface")
					return
				}
				framer := http2.NewFramer(secured, secured)
				if err = framer.WriteSettings(); err != nil {
					return
				}
				for {
					frame, err := framer.ReadFrame()
					if err != nil {
						return
					}
					switch frame := frame.(type) {
					case *http2.HeadersFrame, *http2.DataFrame:
						t.Error("probe sent a notification request")
						return
					case *http2.SettingsFrame:
						if !frame.IsAck() {
							if err = framer.WriteSettingsAck(); err != nil {
								return
							}
						}
					case *http2.PingFrame:
						if frame.IsAck() {
							continue
						}
						receivedPing.Store(true)
						switch mode {
						case "ack":
							err = framer.WritePing(true, frame.Data)
						case "wrong ack":
							data := frame.Data
							data[0] ^= 1
							err = framer.WritePing(true, data)
						case "goaway":
							framer.WriteGoAway(0, http2.ErrCodeInadequateSecurity, []byte("private peer diagnostics"))
							return
						}
						if err != nil {
							return
						}
					}
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			err = probeAPNsConnection(ctx, fixture.client, loopbackAPNsDialer(t, listener.Addr().String()), fixture.serverRoots)
			cancel()
			if mode != "closed" && !receivedPing.Load() {
				t.Fatal("peer did not receive the probe PING")
			}
			if mode == "ack" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err != ErrPushConnection {
				t.Fatal("missing valid HTTP2 acknowledgement accepted", err)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("probe retained its connection")
			}
		})
	}
}
