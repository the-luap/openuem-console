//go:build linux || darwin

package acmeissuer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/gateway"
)

func fixtureConfig(t *testing.T) (Config, string) {
	t.Helper()
	directory := t.TempDir()
	provider := filepath.Join(directory, "provider.json")
	writeFixture(t, provider, []byte(`{"HTTPREQ_ENDPOINT":"http://127.0.0.1:1","HTTPREQ_PASSWORD":"synthetic-test-only"}`))
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return Config{Version: 1, PublicOrigin: "https://uem.example.test", DirectoryURL: "https://127.0.0.1:14000/dir",
		Email: "operator@example.test", AcceptTerms: true, Provider: "httpreq", ProviderEnvironmentFile: provider,
		StateDirectory: filepath.Join(directory, "state"), PublicationDirectory: filepath.Join(directory, "public"), AttemptTimeout: "10s"}, binary
}

func writeFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func fixturePair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: []string{"uem.example.test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

func TestIssuerRejectsAmbiguousJSON(t *testing.T) {
	for _, document := range []string{
		`{"version":1,"version":2}`,
		`{"version":1,"VERSION":2}`,
		`{"nested":{"key":"one","key":"two"}}`,
		`[{"key":"one","key":"two"}]`,
		`{"HTTPREQ_PASSWORD":"one","HTTPREQ_PASSWORD":"two"}`,
		`{} {}`,
	} {
		var value any
		if decodeJSON([]byte(document), &value) == nil {
			t.Fatalf("accepted ambiguous JSON: %s", document)
		}
	}
	var value any
	if decodeJSON([]byte(`{"nested":[{"key":"one"},{"key":"two"}]}`), &value) != nil {
		t.Fatal("independent object keys were rejected")
	}
}

func TestIssuerRejectsUnpairedRestores(t *testing.T) {
	for _, missing := range []string{"state", "publication"} {
		t.Run(missing, func(t *testing.T) {
			c, binary := fixtureConfig(t)
			service := fixtureService(t, c, binary)
			service.Close()
			if missing == "state" {
				c.StateDirectory += "-empty"
			} else {
				c.PublicationDirectory += "-empty"
			}
			if other, err := Open(c, binary); !errors.Is(err, ErrState) {
				if other != nil {
					other.Close()
				}
				t.Fatal("unpaired state was accepted", err)
			}
		})
	}
	c, binary := fixtureConfig(t)
	first := fixtureService(t, c, binary)
	first.Close()
	other, _ := fixtureConfig(t)
	second := fixtureService(t, other, binary)
	second.Close()
	c.PublicationDirectory = other.PublicationDirectory
	if service, err := Open(c, binary); !errors.Is(err, ErrState) {
		if service != nil {
			service.Close()
		}
		t.Fatal("different installation publication was accepted", err)
	}
}

func TestIssuerDoesNotReplaceLostAccountIdentity(t *testing.T) {
	for _, damage := range []string{"missing key", "replaced key", "missing binding", "malformed binding"} {
		t.Run(damage, func(t *testing.T) {
			c, binary := fixtureConfig(t)
			service := fixtureService(t, c, binary)
			certificate, key := fixturePair(t)
			seedResult(t, c, certificate, key)
			result, err := service.Once(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			service.Close()
			accountPath := filepath.Join(c.StateDirectory, accountKeyPath(c))
			bindingPath := filepath.Join(c.StateDirectory, "account-key.json")
			switch damage {
			case "missing key":
				err = os.Remove(accountPath)
			case "replaced key":
				_, otherKey := fixturePair(t)
				writeFixture(t, accountPath, otherKey)
			case "missing binding":
				err = os.Remove(bindingPath)
			case "malformed binding":
				writeFixture(t, bindingPath, []byte(`{"version":1`))
			}
			if err != nil {
				t.Fatal(err)
			}
			if restarted, err := Open(c, binary); !errors.Is(err, ErrState) {
				if restarted != nil {
					restarted.Close()
				}
				t.Fatal("damaged account admitted a replacement", err)
			}
			current, err := os.Readlink(filepath.Join(c.PublicationDirectory, "current"))
			if err != nil || current != result.Generation.Name {
				t.Fatal("damaged account changed publication", err)
			}
		})
	}
}

func TestIssuerRetainsAccountAfterFailedFirstChallenge(t *testing.T) {
	c, binary := fixtureConfig(t)
	service := fixtureService(t, c, binary)
	service.runner = func(context.Context, string, string, []string, []string) error {
		certificate, key := fixturePair(t)
		seedResult(t, c, certificate, key)
		return ErrIssuance
	}
	if _, err := service.Once(t.Context()); !errors.Is(err, ErrIssuance) {
		t.Fatal(err)
	}
	service.Close()
	if err := os.Remove(filepath.Join(c.StateDirectory, accountKeyPath(c))); err != nil {
		t.Fatal(err)
	}
	if restarted, err := Open(c, binary); !errors.Is(err, ErrState) {
		if restarted != nil {
			restarted.Close()
		}
		t.Fatal("failed first challenge lost its account protection", err)
	}
}

func TestIssuerInvalidResultsDoNotAccumulateStages(t *testing.T) {
	c, binary := fixtureConfig(t)
	service := fixtureService(t, c, binary)
	certificate, key := fixturePair(t)
	seedResult(t, c, certificate, key)
	if _, err := service.Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, mismatched := fixturePair(t)
	seedResult(t, c, certificate, mismatched)
	for range 3 {
		if _, err := service.Once(t.Context()); !errors.Is(err, ErrPublication) {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(c.PublicationDirectory)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if generationName(entry.Name()) {
			count++
		}
	}
	if count != 1 {
		t.Fatal("failed attempts accumulated stages", count)
	}
}

func seedResult(t *testing.T, config Config, certificate, key []byte) {
	t.Helper()
	accountPath := filepath.Join(config.StateDirectory, accountKeyPath(config))
	if _, err := os.Stat(accountPath); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(accountPath), 0700); err != nil {
			t.Fatal(err)
		}
		writeFixture(t, accountPath, key)
	}
	directory := filepath.Join(config.StateDirectory, "lego", "certificates")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(directory, "gateway.crt"), certificate)
	writeFixture(t, filepath.Join(directory, "gateway.key"), key)
}

func fixtureService(t *testing.T, config Config, binary string) *Service {
	t.Helper()
	service, err := Open(config, binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	service.runner = func(context.Context, string, string, []string, []string) error { return nil }
	return service
}

func TestIssuerPublicationSurvivesPartialOutputAndRestart(t *testing.T) {
	c, binary := fixtureConfig(t)
	service := fixtureService(t, c, binary)
	certificate, key := fixturePair(t)
	seedResult(t, c, certificate, key)
	result, err := service.Once(t.Context())
	if err != nil || !result.Published || result.Phase != "ready" {
		t.Fatal("initial publication", result, err)
	}
	first := *result.Generation
	link, err := os.Readlink(filepath.Join(c.PublicationDirectory, "current"))
	if err != nil || link != first.Name {
		t.Fatal("generation was not atomically selected", link, err)
	}
	verify := func(want []byte) {
		t.Helper()
		certificatePath, keyPath := filepath.Join(c.PublicationDirectory, "current", "fullchain.pem"), filepath.Join(c.PublicationDirectory, "current", "private.pem")
		if _, err := gateway.NewPublicTLS(c.PublicOrigin, certificatePath, keyPath); err != nil {
			t.Fatal("published pair cannot start the gateway", err)
		}
		actual, err := os.ReadFile(certificatePath)
		if err != nil || !bytes.Equal(actual, want) {
			t.Fatal("wrong published certificate", err)
		}
	}
	verify(certificate)
	result, err = service.Once(t.Context())
	if err != nil || result.Published || result.Generation.Name != first.Name {
		t.Fatal("unchanged result created another generation", result, err)
	}
	_, wrongKey := fixturePair(t)
	seedResult(t, c, certificate, wrongKey)
	if result, err := service.Once(t.Context()); !errors.Is(err, ErrPublication) || result.Published {
		t.Fatal("mismatched output was published", result, err)
	}
	verify(certificate)
	writeFixture(t, filepath.Join(c.StateDirectory, "lego", "certificates", "gateway.key"), []byte("unfinished private key"))
	if _, err := service.Once(t.Context()); !errors.Is(err, ErrPublication) {
		t.Fatal("partial output accepted", err)
	}
	verify(certificate)
	service.Close()
	service = fixtureService(t, c, binary)
	secondCertificate, secondKey := fixturePair(t)
	seedResult(t, c, secondCertificate, secondKey)
	result, err = service.Once(t.Context())
	if err != nil || !result.Published || result.Generation.Name == first.Name {
		t.Fatal("renewal after restart", result, err)
	}
	verify(secondCertificate)
	old, err := os.ReadFile(filepath.Join(c.PublicationDirectory, first.Name, "private.pem"))
	if err != nil || !bytes.Equal(old, key) {
		t.Fatal("old immutable generation was changed", err)
	}
}

func TestIssuerAdmissionBindsRetainedStateAndExcludesOtherWriters(t *testing.T) {
	c, binary := fixtureConfig(t)
	service := fixtureService(t, c, binary)
	if other, err := Open(c, binary); !errors.Is(err, ErrLocked) {
		if other != nil {
			other.Close()
		}
		t.Fatal("second state owner admitted", err)
	}
	otherConfig := c
	otherConfig.StateDirectory = filepath.Join(filepath.Dir(c.StateDirectory), "other-state")
	if other, err := Open(otherConfig, binary); !errors.Is(err, ErrLocked) {
		if other != nil {
			other.Close()
		}
		t.Fatal("second publication owner admitted", err)
	}
	entered, finish := make(chan struct{}), make(chan struct{})
	service.runner = func(ctx context.Context, _ string, _ string, _ []string, _ []string) error {
		close(entered)
		<-finish
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := service.Once(ctx); done <- err }()
	<-entered
	if _, err := service.Once(t.Context()); !errors.Is(err, ErrLocked) {
		t.Fatal("concurrent call bypassed the service lease", err)
	}
	closed := make(chan struct{})
	go func() { service.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("close released ownership before child work joined")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	close(finish)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled operation published a result", err)
	}
	<-closed
	service = fixtureService(t, c, binary)
	service.Close()
	for _, change := range []func(*Config){
		func(c *Config) { c.PublicOrigin = "https://other.example.test" },
		func(c *Config) { c.DirectoryURL = "https://other-ca.example.test/directory" },
		func(c *Config) { c.Email = "other@example.test" },
		func(c *Config) { c.Provider = "cloudflare" },
	} {
		changed := c
		change(&changed)
		if other, err := Open(changed, binary); !errors.Is(err, ErrState) {
			if other != nil {
				other.Close()
			}
			t.Fatal("retained installation was rebound", err)
		}
	}
	if err := os.Remove(filepath.Join(c.StateDirectory, "installation.json")); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(c, binary); !errors.Is(err, ErrState) {
		if other != nil {
			other.Close()
		}
		t.Fatal("partial restore recreated missing identity binding", err)
	}
}

func TestIssuerRejectsUnsafeConfigurationAndProviderOverrides(t *testing.T) {
	c, binary := fixtureConfig(t)
	for _, change := range []func(*Config){
		func(c *Config) { c.AcceptTerms = false }, func(c *Config) { c.PublicOrigin = "http://uem.example.test" },
		func(c *Config) { c.PublicOrigin = "https://uem.example.test:80" }, func(c *Config) { c.PublicOrigin = "https://*.example.test" },
		func(c *Config) { c.PublicOrigin = "https://127.0.0.1" }, func(c *Config) { c.PublicOrigin = "https://uem.example.test/" },
		func(c *Config) { c.DirectoryURL = "http://localhost:14000/dir" }, func(c *Config) { c.Provider = "manual" },
		func(c *Config) { c.DirectoryURL = "https://../directory" }, func(c *Config) { c.Email = "../../account@example.test" },
		func(c *Config) { c.PublicOrigin = "https://uem.example.test:" }, func(c *Config) { c.DirectoryURL = "https://ca.example.test:0/directory" },
		func(c *Config) { c.Provider = "httpreq --http" }, func(c *Config) { c.CheckInterval = "1s" },
		func(c *Config) { c.AttemptTimeout = "0s" }, func(c *Config) { c.Resolvers = []string{"1.1.1.1:domain"} },
		func(c *Config) { c.PublicationDirectory = filepath.Join(c.StateDirectory, "public") },
		func(c *Config) { c.ProviderEnvironmentFile = filepath.Join(c.PublicationDirectory, "provider.json") },
	} {
		changed := c
		change(&changed)
		if err := changed.Validate(); !errors.Is(err, ErrConfiguration) {
			t.Fatal("unsafe configuration accepted", changed, err)
		}
	}
	for _, name := range []string{"LEGO_HTTP", "LEGO_CONFIG", "LEGO_TLS_SKIP_VERIFY", "HTTP_PROXY", "HTTPS_PROXY", "LD_PRELOAD", "HOME", "PATH", "GODEBUG"} {
		data, _ := json.Marshal(map[string]string{name: "untrusted-value"})
		writeFixture(t, c.ProviderEnvironmentFile, data)
		if service, err := Open(c, binary); !errors.Is(err, ErrConfiguration) {
			if service != nil {
				service.Close()
			}
			t.Fatal("provider override accepted", name, err)
		}
	}
	if _, err := os.Stat(c.StateDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid configuration mutated retained state", err)
	}
	secret := filepath.Join(filepath.Dir(c.StateDirectory), "secret")
	writeFixture(t, secret, []byte("synthetic-secret"))
	data, _ := json.Marshal(map[string]string{"HTTPREQ_PASSWORD_FILE": secret})
	writeFixture(t, c.ProviderEnvironmentFile, data)
	if _, err := c.providerEnvironment(); err != nil {
		t.Fatal("protected provider secret file rejected", err)
	}
	if err := os.Chmod(secret, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.providerEnvironment(); !errors.Is(err, ErrConfiguration) {
		t.Fatal("broadly readable provider secret accepted", err)
	}
}

func TestIssuerDoesNotInheritAmbientCredentialsOrPublishAfterFailure(t *testing.T) {
	c, binary := fixtureConfig(t)
	service := fixtureService(t, c, binary)
	certificate, key := fixturePair(t)
	seedResult(t, c, certificate, key)
	if _, err := service.Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_HTTP", "true")
	t.Setenv("LEGO_TLS_SKIP_VERIFY", "true")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "unrelated-ambient-secret")
	service.runner = func(_ context.Context, _ string, _ string, args, env []string) error {
		joined := strings.Join(args, "\n")
		if strings.Contains(joined, "--http\n") || !strings.Contains(joined, "--dns\nhttpreq") || !strings.Contains(joined, "--tls-skip-verify=false") {
			t.Error("DNS-only TLS-verifying arguments were not fixed")
		}
		for _, item := range env {
			if strings.HasPrefix(item, "LEGO_") || strings.Contains(item, "unrelated-ambient-secret") {
				t.Error("ambient credential or challenge override inherited")
			}
		}
		return ErrIssuance
	}
	before, _ := os.Readlink(filepath.Join(c.PublicationDirectory, "current"))
	result, err := service.Once(t.Context())
	if !errors.Is(err, ErrIssuance) || result.Published {
		t.Fatal("failed issuance published a result", result, err)
	}
	after, _ := os.Readlink(filepath.Join(c.PublicationDirectory, "current"))
	if before != after {
		t.Fatal("failed issuance changed the current generation")
	}
	if strings.Contains(LogLine(result, errors.New("synthetic-test-only")), "synthetic-test-only") {
		t.Fatal("provider output reached logs")
	}
	status, err := os.ReadFile(filepath.Join(c.StateDirectory, "status.json"))
	if err != nil || bytes.Contains(status, []byte("synthetic-test-only")) || bytes.Contains(status, []byte(c.Email)) {
		t.Fatal("status leaked provider or account material", err)
	}
}

func TestIssuerRetentionPreservesCurrentAndUnrecognizedFiles(t *testing.T) {
	c, binary := fixtureConfig(t)
	service := fixtureService(t, c, binary)
	var first, current string
	for i := 0; i < 8; i++ {
		certificate, key := fixturePair(t)
		seedResult(t, c, certificate, key)
		result, err := service.Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		current = result.Generation.Name
		if i == 0 {
			first = current
			writeFixture(t, filepath.Join(c.PublicationDirectory, first, "operator-note.txt"), []byte("retain this unrecognized directory"))
		}
	}
	if _, err := os.Stat(filepath.Join(c.PublicationDirectory, first, "operator-note.txt")); err != nil {
		t.Fatal("retention deleted unrecognized contents", err)
	}
	entries, err := os.ReadDir(c.PublicationDirectory)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if generationName(entry.Name()) {
			count++
		}
	}
	if count != 6 {
		t.Fatal("retention did not keep five complete generations plus the unrecognized directory", count)
	}
	link, _ := os.Readlink(filepath.Join(c.PublicationDirectory, "current"))
	if link != current {
		t.Fatal("retention changed the selected generation")
	}
}

func TestIssuerRejectsRootReplacementAndCorruptCurrentKey(t *testing.T) {
	t.Run("root replacement", func(t *testing.T) {
		c, binary := fixtureConfig(t)
		service := fixtureService(t, c, binary)
		if err := os.Rename(c.StateDirectory, c.StateDirectory+"-retained"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(c.StateDirectory, 0700); err != nil {
			t.Fatal(err)
		}
		called := false
		service.runner = func(context.Context, string, string, []string, []string) error { called = true; return nil }
		if _, err := service.Once(t.Context()); !errors.Is(err, ErrState) || called {
			t.Fatal("replaced root admitted child work", err)
		}
		entries, _ := os.ReadDir(c.StateDirectory)
		if len(entries) != 0 {
			t.Fatal("replaced state root was modified")
		}
	})
	t.Run("corrupt current key", func(t *testing.T) {
		c, binary := fixtureConfig(t)
		service := fixtureService(t, c, binary)
		certificate, key := fixturePair(t)
		seedResult(t, c, certificate, key)
		result, err := service.Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		service.Close()
		writeFixture(t, filepath.Join(c.PublicationDirectory, result.Generation.Name, "private.pem"), []byte("incomplete restore"))
		if other, err := Open(c, binary); !errors.Is(err, ErrState) {
			if other != nil {
				other.Close()
			}
			t.Fatal("corrupt retained key admitted", err)
		}
	})
}

func TestIssuerCanReplaceAnExpiredRetainedGeneration(t *testing.T) {
	c, binary := fixtureConfig(t)
	service := fixtureService(t, c, binary)
	certificate, key := fixturePair(t)
	seedResult(t, c, certificate, key)
	result, err := service.Once(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	service.Close()
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := pair.Leaf
	leaf.NotBefore = time.Now().Add(-2 * time.Hour)
	leaf.NotAfter = time.Now().Add(-time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, leaf.PublicKey, pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	oldCertificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	writeFixture(t, filepath.Join(c.PublicationDirectory, result.Generation.Name, "fullchain.pem"), oldCertificate)
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(oldCertificate)
	result.Generation.CertificateSHA256 = hex.EncodeToString(digest[:])
	result.Generation.NotBefore = parsed.NotBefore
	result.Generation.NotAfter = parsed.NotAfter
	metadata, _ := json.Marshal(result.Generation)
	writeFixture(t, filepath.Join(c.PublicationDirectory, result.Generation.Name, "generation.json"), metadata)
	service = fixtureService(t, c, binary)
	certificate, key = fixturePair(t)
	seedResult(t, c, certificate, key)
	result, err = service.Once(t.Context())
	if err != nil || !result.Published || !result.Generation.NotAfter.After(time.Now()) {
		t.Fatal("expired retained generation blocked safe renewal", result, err)
	}
}
