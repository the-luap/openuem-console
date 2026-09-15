//go:build linux || darwin

package acmeissuer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type accountBinding struct {
	Version int    `json:"version"`
	KeyPath string `json:"key_path"`
	SHA256  string `json:"sha256"`
}

// This path follows the pinned lego v5 account layout. Config validation rejects
// path separators in the email and non-host names in the directory authority.
func accountKeyPath(c Config) string {
	u, _ := url.Parse(c.DirectoryURL)
	host := strings.NewReplacer(":", "_", "/", "_", `\`, "_").Replace(u.Host)
	return filepath.Join("lego", "accounts", host, c.Email, c.Email+".key")
}

// Guard against lego's automatic replacement of a missing account key. A
// published installation requires the existing fingerprint before any child runs.
// A newly created account is durably bound even if the DNS challenge then fails.
func (d *directory) account(c Config, requireBinding, requireKey, retain bool) error {
	if d.unchanged() != nil {
		return ErrState
	}
	var binding *accountBinding
	if _, err := d.root.Lstat("account-key.json"); err == nil {
		data, err := readProtected(filepath.Join(d.path, "account-key.json"), 8192, true)
		if err != nil || decodeJSON(data, &binding) != nil || binding == nil || binding.Version != 1 || binding.KeyPath != accountKeyPath(c) {
			return ErrState
		}
	} else if !errors.Is(err, os.ErrNotExist) || requireBinding {
		return ErrState
	}
	keyPath := accountKeyPath(c)
	file, err := d.root.OpenFile(keyPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		if binding != nil || requireKey {
			return ErrState
		}
		// Registration data without its private key is a partial restore, even
		// when interruption prevented writing the fingerprint on the first run.
		if _, err := d.root.Lstat(filepath.Join(filepath.Dir(keyPath), "account.json")); !errors.Is(err, os.ErrNotExist) {
			return ErrState
		}
		return nil
	}
	if err != nil {
		return ErrState
	}
	defer file.Close()
	key, err := readProtectedFile(file, 64<<10, true)
	if err != nil {
		return ErrState
	}
	defer clear(key)
	block, rest := pem.Decode(key)
	if block == nil || len(block.Headers) != 0 || strings.TrimSpace(string(rest)) != "" || !bytes.HasPrefix(key, []byte("-----BEGIN ")) || bytes.Count(key, []byte("-----BEGIN ")) != 1 {
		return ErrState
	}
	var parsed any
	switch block.Type {
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return ErrState
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); err != nil || !ok {
		return ErrState
	}
	digest := sha256.Sum256(key)
	fingerprint := hex.EncodeToString(digest[:])
	if binding != nil {
		if binding.SHA256 != fingerprint {
			return ErrState
		}
		return nil
	}
	if !retain {
		return nil
	}
	// Lego writes account files in place. Make the original key and every new
	// directory entry durable before recording its fingerprint or publishing TLS.
	if file.Sync() != nil {
		return ErrState
	}
	for parent := filepath.Dir(keyPath); ; parent = filepath.Dir(parent) {
		directory, err := d.root.Open(parent)
		if err != nil {
			return ErrState
		}
		err = directory.Sync()
		closeErr := directory.Close()
		if err != nil || closeErr != nil {
			return ErrState
		}
		if parent == "." {
			break
		}
	}
	encoded, err := json.Marshal(accountBinding{1, keyPath, fingerprint})
	if err != nil || writeExclusive(d.root, "account-key.json", encoded) != nil || syncRoot(d.root) != nil {
		return ErrState
	}
	return nil
}
