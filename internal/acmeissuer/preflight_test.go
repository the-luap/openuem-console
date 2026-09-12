//go:build linux || darwin

package acmeissuer

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestIssuerInputCheckDoesNotCreateOrLockState(t *testing.T) {
	c, binary := fixtureConfig(t)
	if err := c.CheckInputs(binary); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{c.StateDirectory, c.PublicationDirectory} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("input check created issuer state", err)
		}
	}
	service, err := Open(c, binary)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	snapshot := func() map[string][32]byte {
		t.Helper()
		result := map[string][32]byte{}
		for _, root := range []string{c.StateDirectory, c.PublicationDirectory} {
			if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
				if err != nil || entry.IsDir() {
					return err
				}
				data, err := os.ReadFile(path)
				result[path] = sha256.Sum256(data)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	before := snapshot()
	// The running service holds both exclusive leases. Input validation must
	// remain possible without adopting or claiming to validate this account.
	if err := c.CheckInputs(binary); err != nil {
		t.Fatal("read-only input check tried to acquire an issuer lease", err)
	}
	if !reflect.DeepEqual(before, snapshot()) {
		t.Fatal("read-only input check changed retained issuer state")
	}
}

func TestIssuerInputCheckRejectsProtectedInputLossBeforeStateCreation(t *testing.T) {
	c, binary := fixtureConfig(t)
	if err := os.Remove(c.ProviderEnvironmentFile); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckInputs(binary); !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing provider input was accepted", err)
	}
	for _, path := range []string{c.StateDirectory, c.PublicationDirectory} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("rejected input check created issuer state", err)
		}
	}
}

func TestIssuerInputCheckRequiresCompleteCertificateOnlyACMETrust(t *testing.T) {
	c, binary := fixtureConfig(t)
	certificate, key := fixturePair(t)
	c.ACMERootsFile = filepath.Join(filepath.Dir(c.StateDirectory), "acme-roots.pem")
	writeFixture(t, c.ACMERootsFile, certificate)
	if err := c.CheckInputs(binary); err != nil {
		t.Fatal("explicit certificate trust was rejected", err)
	}
	for _, data := range [][]byte{
		[]byte("not a certificate"),
		append(bytes.Clone(certificate), key...),
		append([]byte("unrecognized prefix\n"), certificate...),
		append(bytes.Clone(certificate), []byte("trailing data")...),
		[]byte("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"),
		append([]byte("-----BEGIN CERTIFICATE-----\ninvalid base64\n-----END CERTIFICATE-----\n"), certificate...),
		bytes.Repeat(certificate, 129),
	} {
		writeFixture(t, c.ACMERootsFile, data)
		if err := c.CheckInputs(binary); !errors.Is(err, ErrConfiguration) {
			t.Fatal("malformed or mixed ACME trust was accepted", err)
		}
	}
	for _, path := range []string{c.StateDirectory, c.PublicationDirectory} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("ACME trust validation created state", err)
		}
	}
}
