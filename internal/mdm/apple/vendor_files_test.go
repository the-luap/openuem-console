package apple

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/open-uem/nats/enrollment/keyfile"
)

func TestVendorSigningFilesProtectKeysAndExistingOutput(t *testing.T) {
	f := newVendorFixture(t)
	dir := t.TempDir()
	csrPath, chainPath, keyPath, outputPath := filepath.Join(dir, "public.csr"), filepath.Join(dir, "chain.pem"), filepath.Join(dir, "vendor-key.pem"), filepath.Join(dir, "portal.plist")
	der, err := x509.MarshalPKCS8PrivateKey(f.key)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for path, data := range map[string][]byte{csrPath: f.csr, chainPath: f.chainPEM, keyPath: encodedKey} {
		if err := keyfile.Create(path, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.trust.SignVendorFiles(csrPath, chainPath, keyPath, outputPath); err != nil {
		t.Fatal(err)
	}
	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.trust.VerifyPortalRequest(f.csr, output, f.now); err != nil {
		t.Fatal("file output is not a signed portal request", err)
	}
	if bytes.Contains(output, []byte("PRIVATE KEY")) || bytes.Equal(output, encodedKey) {
		t.Fatal("private key exported")
	}
	if err := f.trust.SignVendorFiles(csrPath, chainPath, keyPath, outputPath); err == nil {
		t.Fatal("existing output overwritten")
	}
	unchanged, err := os.ReadFile(outputPath)
	if err != nil || !bytes.Equal(unchanged, output) {
		t.Fatal("existing output changed", err)
	}
	production, err := NewVendorTrust([]string{digest(f.chain[0].Raw)})
	if err != nil {
		t.Fatal(err)
	}
	if err := production.SignVendorFiles(csrPath, chainPath, keyPath, filepath.Join(dir, "untrusted.plist")); err == nil {
		t.Fatal("production signed using a synthetic Apple root")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(keyPath, 0644); err != nil {
			t.Fatal(err)
		}
		if err := f.trust.SignVendorFiles(csrPath, chainPath, keyPath, filepath.Join(dir, "shared-key.plist")); err == nil {
			t.Fatal("shared vendor private key accepted")
		}
	}
}

func TestVendorPrivateKeyTypeAndEncoding(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"wrong-algorithm": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"incomplete":      []byte("-----BEGIN PRIVATE KEY-----\npartial"),
		"non-key":         []byte("not a key"),
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "key.pem")
			if err := keyfile.Create(p, data); err != nil {
				t.Fatal(err)
			}
			if _, err := loadVendorPrivateKey(p); err == nil {
				t.Fatal("invalid private key accepted")
			}
		})
	}
}
