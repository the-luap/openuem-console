package apple

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"

	"golang.org/x/net/http2"
)

const apnsProductionHost = "api.push.apple.com"
const apnsCheckTimeout = 10 * time.Second

var ErrPushConnection = errors.New("the APNs connection check failed; verify outbound TCP 443 access, server trust and the Apple certificate, then retry the import; active credentials and pending requests have not changed")

// checkAPNsConnection always uses a new connection and the candidate credential.
// No device token, push payload, HTTP request, proxy or alternate host is used.
func checkAPNsConnection(ctx context.Context, c *Settings) error {
	if c == nil {
		return ErrPushConnection
	}
	certificate, err := tls.X509KeyPair(c.PushCertificate, c.PushKey)
	if err != nil {
		return ErrPushConnection
	}
	return probeAPNsConnection(ctx, certificate, (&net.Dialer{}).DialContext, nil)
}

// The dialer and server roots are private seams for loopback TLS tests. There is
// no production option to redirect this check or disable server verification.
func probeAPNsConnection(parent context.Context, certificate tls.Certificate, dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) error {
	ctx, cancel := context.WithTimeout(parent, apnsCheckTimeout)
	defer cancel()
	if ctx.Err() != nil || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil || dial == nil {
		return ErrPushConnection
	}
	connection, err := dial(ctx, "tcp", net.JoinHostPort(apnsProductionHost, "443"))
	if err != nil {
		return ErrPushConnection
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = connection.SetDeadline(deadline); err != nil {
		return ErrPushConnection
	}
	presented := false
	secured := tls.Client(connection, &tls.Config{
		ServerName: apnsProductionHost,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{http2.NextProtoTLS},
		GetClientCertificate: func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if err := request.SupportsCertificate(&certificate); err != nil {
				return nil, ErrPushConnection
			}
			presented = true
			return &certificate, nil
		},
	})
	if err = secured.HandshakeContext(ctx); err != nil || !presented || secured.ConnectionState().NegotiatedProtocol != http2.NextProtoTLS {
		return ErrPushConnection
	}
	transport := &http2.Transport{MaxReadFrameSize: 16 << 10, MaxHeaderListSize: 4096, MaxDecoderHeaderTableSize: 4096}
	client, err := transport.NewClientConn(secured)
	if err != nil {
		return ErrPushConnection
	}
	defer func() {
		// Closing the raw connection first also unblocks TLS writes on failure.
		connection.Close()
		client.Close()
	}()
	// A handshake alone can return before a TLS 1.3 peer's rejection is read.
	// Require an HTTP/2 PING acknowledgement after presenting the certificate.
	// This proves a working connection, not push delivery or MDM acknowledgement.
	if err = client.Ping(ctx); err != nil || !client.CanTakeNewRequest() || ctx.Err() != nil {
		return ErrPushConnection
	}
	return nil
}
