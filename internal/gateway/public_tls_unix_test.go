//go:build linux || darwin

package gateway

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPublicTLSAtomicACMEDirectorySwitch(t *testing.T) {
	f := newPublicTLSFixture(t)
	first, second := f.issue(t, nil), f.issue(t, nil)
	root := t.TempDir()
	for name, pair := range map[string]tls.Certificate{"first": first, "second": second} {
		directory := filepath.Join(root, name)
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		generation := *f
		generation.certificatePath = filepath.Join(directory, "fullchain.pem")
		generation.keyPath = filepath.Join(directory, "private.pem")
		generation.publish(t, pair)
	}
	current := filepath.Join(root, "current")
	if err := os.Symlink("first", current); err != nil {
		t.Fatal(err)
	}
	publicTLS, err := NewPublicTLS("https://uem.example.test", filepath.Join(current, "fullchain.pem"), filepath.Join(current, "private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	switchTo := func(target string) {
		t.Helper()
		if err := os.Symlink(target, current+".next"); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(current+".next", current); err != nil {
			t.Fatal(err)
		}
	}
	switchTo("second")
	if changed, err := publicTLS.Reload(); err != nil || !changed {
		t.Fatal("atomic generation switch failed", changed, err)
	}
	server := publicTLSServer(t, publicTLS)
	response := getPublicTLS(t, publicTLSClient(t, f.clientTLS(), true), server.URL)
	if !response.TLS.PeerCertificates[0].Equal(second.Leaf) {
		t.Fatal("new handshake did not select the new archive generation")
	}
	switchTo("incomplete")
	if changed, err := publicTLS.Reload(); err == nil || changed {
		t.Fatal("broken archive link replaced valid generation")
	}
	response = getPublicTLS(t, publicTLSClient(t, f.clientTLS(), true), server.URL)
	if !response.TLS.PeerCertificates[0].Equal(second.Leaf) {
		t.Fatal("broken archive link discarded the loaded generation")
	}
	switchTo("second")
	if changed, err := publicTLS.Reload(); err != nil || changed {
		t.Fatal("restored archive link was not recovered", changed, err)
	}
}

func TestPublicTLSRejectsLocalFIFOs(t *testing.T) {
	f := newPublicTLSFixture(t)
	f.publish(t, f.issue(t, nil))
	if err := os.Remove(f.keyPath); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(f.keyPath, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPublicTLS("https://uem.example.test", f.certificatePath, f.keyPath); err == nil {
		t.Fatal("FIFO accepted as a private key file")
	}
}
