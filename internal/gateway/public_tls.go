package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	errPublicTLSFiles       = errors.New("public TLS files must contain a readable, bounded certificate and matching private key")
	errPublicTLSCertificate = errors.New("public TLS certificate chain must be currently valid for the configured HTTPS hostname and server authentication")
	errPublicTLSExpired     = errors.New("no currently valid public TLS certificate is loaded")
)

// PublicTLS reloads administrator-managed local certificate files without closing
// established HTTP or agent connections. Failed publication retains the previous
// pair; it cannot extend that pair's validity for a new TLS handshake.
type PublicTLS struct {
	certificatePath, keyPath, hostname string
	now                                func() time.Time
	reloadMu                           sync.Mutex
	current                            atomic.Pointer[publicTLSCertificate]
}

type publicTLSCertificate struct {
	config              *tls.Config
	digest              [sha256.Size]byte
	notBefore, notAfter time.Time
}

func NewPublicTLS(origin, certificatePath, keyPath string) (*PublicTLS, error) {
	return newPublicTLS(origin, certificatePath, keyPath, time.Now)
}

func newPublicTLS(origin, certificatePath, keyPath string, now func() time.Time) (*PublicTLS, error) {
	u, err := ParseOrigin(origin)
	if err != nil {
		return nil, err
	}
	p := &PublicTLS{certificatePath: certificatePath, keyPath: keyPath, hostname: u.Hostname(), now: now}
	if _, err = p.Reload(); err != nil {
		return nil, err
	}
	return p, nil
}

func publicTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// TLS proves possession; the private backend validates end-client trust.
		ClientAuth: tls.RequestClientCert,
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// Config checks validity before every ClientHello, including session resumption.
// Neither the returned configuration nor its callbacks perform file I/O. Each
// admitted handshake keeps its own immutable snapshot through concurrent reloads.
func (p *PublicTLS) Config() *tls.Config {
	config := publicTLSConfig()
	config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		certificate := p.current.Load()
		now := p.now()
		if certificate == nil || now.Before(certificate.notBefore) || !now.Before(certificate.notAfter) {
			return nil, errPublicTLSExpired
		}
		return certificate.config, nil
	}
	return config
}

// Reload atomically publishes a complete matching pair only after checking the
// hostname, lifetime, server purpose and supplied chain. Certificate authorities
// trusted by remote clients remain those clients' decision, not this file's.
// Concurrent calls are serialized so an older read cannot replace a newer read.
func (p *PublicTLS) Reload() (bool, error) {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()
	certificatePEM, err := readPublicTLSFile(p.certificatePath, 1<<20)
	if err != nil {
		return false, errPublicTLSFiles
	}
	keyPEM, err := readPublicTLSFile(p.keyPath, 64<<10)
	if err != nil {
		return false, errPublicTLSFiles
	}
	defer clear(keyPEM)
	if !validPublicTLSPEM(certificatePEM, true) || !validPublicTLSPEM(keyPEM, false) {
		return false, errPublicTLSFiles
	}
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || len(pair.Certificate) == 0 || len(pair.Certificate) > 8 {
		return false, errPublicTLSFiles
	}
	certificates := make([]*x509.Certificate, len(pair.Certificate))
	digest := sha256.New()
	var notBefore, notAfter time.Time
	for i, der := range pair.Certificate {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return false, errPublicTLSCertificate
		}
		certificates[i] = certificate
		if i == 0 || certificate.NotBefore.After(notBefore) {
			notBefore = certificate.NotBefore
		}
		if i == 0 || certificate.NotAfter.Before(notAfter) {
			notAfter = certificate.NotAfter
		}
		if i > 0 && certificates[i-1].CheckSignatureFrom(certificate) != nil {
			return false, errPublicTLSCertificate
		}
		_, _ = digest.Write(der)
	}
	leaf := certificates[0]
	now := p.now()
	if leaf.IsCA || (leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0) || now.Before(notBefore) || !now.Before(notAfter) {
		return false, errPublicTLSCertificate
	}
	// Validate the supplied path, including intermediate name/purpose constraints.
	// The final supplied certificate is a structural anchor, not newly granted
	// public trust. Clients still verify the served chain against their own roots.
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(certificates[len(certificates)-1])
	for i := 1; i+1 < len(certificates); i++ {
		intermediates.AddCert(certificates[i])
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName: p.hostname, Roots: roots, Intermediates: intermediates,
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return false, errPublicTLSCertificate
	}
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], digest.Sum(nil))
	if current := p.current.Load(); current != nil && current.digest == fingerprint {
		return false, nil
	}
	pair.Leaf = leaf
	config := publicTLSConfig()
	config.Certificates = []tls.Certificate{pair}
	p.current.Store(&publicTLSCertificate{config: config, digest: fingerprint, notBefore: notBefore, notAfter: notAfter})
	return true, nil
}

// tls.X509KeyPair intentionally ignores unrelated or unfinished PEM material.
// A certificate publisher must finish the whole chain and exactly one key before
// that generation can replace the working configuration.
func validPublicTLSPEM(data []byte, certificate bool) bool {
	count := 0
	for len(bytes.TrimSpace(data)) != 0 {
		data = bytes.TrimSpace(data)
		block, rest := pem.Decode(data)
		if block == nil {
			return false
		}
		if !certificate {
			clear(block.Bytes)
		}
		if len(block.Headers) != 0 || !bytes.HasPrefix(data, []byte("-----BEGIN "+block.Type+"-----")) ||
			bytes.Count(data[:len(data)-len(rest)], []byte("-----BEGIN ")) != 1 {
			return false
		}
		count++
		if certificate {
			if block.Type != "CERTIFICATE" || count > 8 {
				return false
			}
		} else if count != 1 || (block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY") {
			return false
		}
		data = rest
	}
	return count != 0
}

// Certificate publishers must control these local paths and their parents. ACME
// archive symlinks and atomic directory switches are supported. Both stat checks
// reject nonregular inputs; the bounded read checks the opened descriptor too.
func readPublicTLSFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, errPublicTLSFiles
	}
	// On Unix, a FIFO substituted between Stat and Open must not leave the
	// reload worker blocked waiting for a writer. Regular files are unaffected.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errPublicTLSFiles
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, errPublicTLSFiles
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(data) < 1 || int64(len(data)) > maximum {
		clear(data)
		return nil, errPublicTLSFiles
	}
	return data, nil
}

// Watch runs synchronously until cancellation. The caller owns and joins its
// goroutine. Reports contain fixed, secret-free errors; repeated failures with
// the same reason are suppressed until the files recover or the reason changes.
func (p *PublicTLS) Watch(ctx context.Context, interval time.Duration, report func(error)) error {
	if interval < time.Second || interval > time.Hour {
		return errors.New("public TLS reload interval must be between one second and one hour")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	p.watch(ctx, ticker.C, report)
	return nil
}

func (p *PublicTLS) watch(ctx context.Context, ticks <-chan time.Time, report func(error)) {
	var lastError error
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok || ctx.Err() != nil {
				return
			}
			changed, err := p.Reload()
			if report != nil && (changed || err != lastError) {
				report(err)
			}
			lastError = err
		}
	}
}
