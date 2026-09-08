package apple

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Apple's software catalog uses an Apple PKI chain which is not present in all
// OS trust stores. The catalog client, vendor envelope verifier and offline push
// import verifier opt into this root; it is never installed in the OS trust store.
// Source and fingerprint are recorded in certs/README.md.
//
//go:embed certs/AppleIncRootCertificate.cer
var appleRootDER []byte

func catalogClient() (*http.Client, error) {
	root, err := x509.ParseCertificate(appleRootDER)
	if err != nil {
		return nil, fmt.Errorf("parse Apple catalog trust anchor: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	roots.AddCert(root)
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("unexpected Apple catalog redirect")
		},
	}, nil
}
