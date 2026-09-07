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
// OS trust stores. Scope this additional root to the fixed catalog client.
// Source and fingerprint are recorded in certs/README.md.
//
//go:embed certs/AppleIncRootCertificate.cer
var appleCatalogRootDER []byte

func catalogClient() (*http.Client, error) {
	root, err := x509.ParseCertificate(appleCatalogRootDER)
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
