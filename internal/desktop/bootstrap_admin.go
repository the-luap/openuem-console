package desktop

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/keyfile"
)

const BootstrapKeyFilename = "bootstrap-signing-key.pem"

// InitBootstrapKey provisions one dedicated configuration key for the current
// console service account. The caller chooses an absolute directory beneath a
// trusted parent. Existing private keys are validated and retained; malformed,
// shared or incomplete files are never overwritten or repaired automatically.
// An interrupted exclusive creation can leave a protected incomplete file and
// must be investigated before another initialization. Output is public metadata.
func InitBootstrapKey(directory string, output io.Writer) error {
	if output == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return ErrBootstrapConfiguration
	}
	if err := keyfile.CreateDirectory(directory); err != nil {
		return ErrBootstrapConfiguration
	}
	path := filepath.Join(directory, BootstrapKeyFilename)
	created := false
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return ErrBootstrapConfiguration
		}
	} else if errors.Is(err, os.ErrNotExist) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return ErrBootstrapConfiguration
		}
		defer clear(key)
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return ErrBootstrapConfiguration
		}
		defer clear(der)
		data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		defer clear(data)
		// Create applies private access controls before writing, uses exclusive
		// creation and syncs the file. A concurrent winner is never replaced.
		if err := keyfile.Create(path, data); err != nil {
			return ErrBootstrapConfiguration
		}
		created = true
	} else {
		return ErrBootstrapConfiguration
	}
	key, err := LoadBootstrapKey(path)
	if err != nil {
		return ErrBootstrapConfiguration
	}
	defer clear(key)
	result := struct {
		KeyID   string `json:"key_id"`
		Created bool   `json:"created"`
	}{artifacts.KeyID(key.Public().(ed25519.PublicKey)), created}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		return errors.New("could not write bootstrap key metadata; the protected key is retained")
	}
	return nil
}
