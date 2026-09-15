//go:build linux || darwin

package acmeissuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func readinessFixture(t *testing.T) (*Service, Config, string) {
	t.Helper()
	c, binary := fixtureConfig(t)
	service := fixtureService(t, c, binary)
	// macOS test directories may exceed Unix socket pathname limits. This
	// separate private temporary parent contains only this test's socket.
	directory, err := os.MkdirTemp("/tmp", "openuem-ready-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	return service, c, filepath.Join(directory, "issuer.sock")
}

func publishReadinessFixture(t *testing.T, service *Service, c Config) {
	t.Helper()
	certificate, key := fixturePair(t)
	seedResult(t, c, certificate, key)
	if _, err := service.Once(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestIssuerReadinessRequiresLiveOwnershipAndOriginalMaterial(t *testing.T) {
	service, c, socket := readinessFixture(t)
	server, err := service.ListenReadiness(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	check := func(ready bool) {
		t.Helper()
		err := CheckReadiness(t.Context(), c, socket)
		if ready && err != nil || !ready && !errors.Is(err, ErrNotReady) {
			t.Fatal("unexpected issuer readiness", ready, err)
		}
	}
	check(false)
	publishReadinessFixture(t, service, c)
	check(true)
	changed := c
	changed.Email = "different@example.test"
	if !errors.Is(CheckReadiness(t.Context(), changed, socket), ErrNotReady) {
		t.Fatal("another reviewed configuration received readiness")
	}
	for _, path := range []string{filepath.Join(c.StateDirectory, accountKeyPath(c)),
		filepath.Join(c.StateDirectory, "account-key.json"), filepath.Join(c.PublicationDirectory, "installation.json")} {
		data, err := os.ReadFile(path)
		if err != nil || os.Remove(path) != nil {
			t.Fatal("fixture state could not be withheld")
		}
		check(false)
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("readiness repaired missing retained state")
		}
		writeFixture(t, path, data)
		check(true)
	}
	for _, directory := range []string{c.StateDirectory, c.PublicationDirectory} {
		path := filepath.Join(directory, "issuer.lock")
		if os.Rename(path, path+"-held") != nil {
			t.Fatal("fixture lease could not be withheld")
		}
		check(false)
		if os.Rename(path+"-held", path) != nil {
			t.Fatal("fixture original lease could not be restored")
		}
		check(true)
	}
	original, _ := os.ReadFile(filepath.Join(c.StateDirectory, "installation.json"))
	var replacement installationBinding
	_ = json.Unmarshal(original, &replacement)
	replacement.Installation = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	changedBinding, _ := json.Marshal(replacement)
	for _, directory := range []string{c.StateDirectory, c.PublicationDirectory} {
		writeFixture(t, filepath.Join(directory, "installation.json"), changedBinding)
	}
	check(false)
	for _, directory := range []string{c.StateDirectory, c.PublicationDirectory} {
		writeFixture(t, filepath.Join(directory, "installation.json"), original)
	}
	check(true)
	service.Close()
	check(false)
	server.Close()
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("closed readiness retained its owned socket")
	}
	check(false)
}

func TestIssuerReadinessRejectsPublicParentsAndSocketAliasesWithoutRepair(t *testing.T) {
	service, c, socket := readinessFixture(t)
	parent := filepath.Dir(socket)
	if os.Chmod(parent, 0755) != nil {
		t.Fatal("fixture directory mode could not be changed")
	}
	if server, err := service.ListenReadiness(socket); !errors.Is(err, ErrNotReady) {
		if server != nil {
			server.Close()
		}
		t.Fatal("readiness accepted a public parent")
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected listener created a socket")
	}
	if os.Chmod(parent, 0700) != nil {
		t.Fatal("fixture directory mode could not be restored")
	}
	writeFixture(t, socket+"-target", []byte("unrelated retained data"))
	if os.Symlink(socket+"-target", socket) != nil {
		t.Fatal("fixture socket alias could not be created")
	}
	if server, err := service.ListenReadiness(socket); !errors.Is(err, ErrNotReady) {
		if server != nil {
			server.Close()
		}
		t.Fatal("readiness accepted an aliased socket")
	}
	if !errors.Is(CheckReadiness(t.Context(), c, socket), ErrNotReady) {
		t.Fatal("readiness probe accepted an aliased socket")
	}
	if info, err := os.Lstat(socket); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("rejected readiness removed an unrelated alias")
	}
}

func TestIssuerReadinessRetainsValidPublicationDuringFailedRenewal(t *testing.T) {
	service, c, socket := readinessFixture(t)
	publishReadinessFixture(t, service, c)
	server, err := service.ListenReadiness(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	service.runner = func(context.Context, string, string, []string, []string) error {
		close(entered)
		<-release
		return ErrIssuance
	}
	done := make(chan error, 1)
	go func() { _, err := service.Once(t.Context()); done <- err }()
	<-entered
	err = CheckReadiness(t.Context(), c, socket)
	close(release)
	if !errors.Is(<-done, ErrIssuance) || err != nil || CheckReadiness(t.Context(), c, socket) != nil {
		t.Fatal("an active or failed renewal discarded ready retained public TLS", err)
	}
}

func TestIssuerReadinessRejectsConsistentButExpiredPublication(t *testing.T) {
	service, c, _ := readinessFixture(t)
	publishReadinessFixture(t, service, c)
	generation, err := service.publication.current(c.PublicOrigin)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(c.PublicationDirectory, generation.Name)
	certificate, _ := os.ReadFile(filepath.Join(directory, "fullchain.pem"))
	key, _ := os.ReadFile(filepath.Join(directory, "private.pem"))
	block, _ := pem.Decode(certificate)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	block, _ = pem.Decode(key)
	private, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	leaf.NotBefore, leaf.NotAfter = time.Now().Add(-2*time.Hour).Truncate(time.Second), time.Now().Add(-time.Hour).Truncate(time.Second)
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &private.(*ecdsa.PrivateKey).PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	digest := sha256.Sum256(certificate)
	generation.CertificateSHA256, generation.NotBefore, generation.NotAfter = hex.EncodeToString(digest[:]), leaf.NotBefore, leaf.NotAfter
	metadata, _ := json.Marshal(generation)
	writeFixture(t, filepath.Join(directory, "fullchain.pem"), certificate)
	writeFixture(t, filepath.Join(directory, "generation.json"), metadata)
	if _, err := service.publication.current(c.PublicOrigin); err != nil {
		t.Fatal("expired fixture must retain consistent publication metadata", err)
	}
	if !errors.Is(service.Ready(), ErrNotReady) {
		t.Fatal("expired but internally consistent certificate was ready")
	}
}

func TestIssuerReadinessPreservesActiveForeignSocketsAndRecoversOwnedStaleSocket(t *testing.T) {
	service, c, socket := readinessFixture(t)
	publishReadinessFixture(t, service, c)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.SetUnlinkOnClose(false)
	if os.Chmod(socket, 0600) != nil {
		t.Fatal("fixture socket could not be protected")
	}
	before, _ := os.Lstat(socket)
	if other, err := service.ListenReadiness(socket); !errors.Is(err, ErrNotReady) {
		if other != nil {
			other.Close()
		}
		t.Fatal("active foreign readiness listener was replaced")
	}
	after, _ := os.Lstat(socket)
	if !os.SameFile(before, after) {
		t.Fatal("active foreign socket was removed")
	}
	_ = listener.Close()
	server, err := service.ListenReadiness(socket)
	if err != nil {
		t.Fatal("stale private socket did not recover under the retained service leases", err)
	}
	defer server.Close()
	if CheckReadiness(t.Context(), c, socket) != nil {
		t.Fatal("recovered local readiness did not respond")
	}
	if err := os.Rename(socket, socket+"-old"); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, socket, []byte("unrelated replacement"))
	server.Close()
	if value, _ := os.ReadFile(socket); string(value) != "unrelated replacement" {
		t.Fatal("readiness shutdown deleted an unexpected replacement")
	}
}

func TestIssuerReadinessClosesConcurrentAndIdleChecks(t *testing.T) {
	service, c, socket := readinessFixture(t)
	publishReadinessFixture(t, service, c)
	server, err := service.ListenReadiness(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	idle, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	_, _ = idle.Write([]byte("GET /ready HTTP/1.1\r\n"))
	var requests sync.WaitGroup
	for range 16 {
		requests.Go(func() {
			if err := CheckReadiness(t.Context(), c, socket); err != nil && !errors.Is(err, ErrNotReady) {
				t.Error("unexpected concurrent readiness result", err)
			}
		})
	}
	server.Close()
	requests.Wait()
	_ = idle.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := idle.Read(make([]byte, 1)); err == nil {
		t.Fatal("readiness shutdown retained an idle connection")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if !errors.Is(CheckReadiness(canceled, c, socket), context.Canceled) {
		t.Fatal("readiness discarded caller cancellation")
	}
}
