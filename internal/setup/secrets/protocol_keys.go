package secrets

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
)

const (
	WindowsKeyFile          = "windows.key"
	DesktopBootstrapKeyFile = "desktop-bootstrap.key"
)

var protocolArtifacts = []string{WindowsKeyFile, DesktopBootstrapKeyFile}

type protocolJournal struct {
	Version      int    `json:"version"`
	Installation string `json:"installation"`
	Foundation   string `json:"foundation"`
	Windows      string `json:"windows"`
	Bootstrap    string `json:"bootstrap"`
}

// InitializeProtocolKeys provisions independent Windows authority encryption and
// desktop bootstrap signing keys. The existing installation directory is a
// read-only input and must be complete. The output is bound to its exact retained
// credentials. Keep both parent directories trusted and back up both journals.
// A retry resumes completed writes; it never overwrites or rotates any key.
func InitializeProtocolKeys(ctx context.Context, directory, installation string) (Result, error) {
	return initializeProtocolKeys(ctx, directory, installation, nil)
}

func initializeProtocolKeys(ctx context.Context, directory, installation string, afterWrite func(string) error) (Result, error) {
	foundation, digest, err := provisionInstallation(ctx, installation, nil, false)
	if err != nil {
		return Result{}, err
	}
	if !separateDirectories(directory, installation) {
		return Result{}, ErrConfiguration
	}
	d, err := openProvisioning(ctx, directory, append([]string{"secrets.json", "manifest.json"}, protocolArtifacts...), afterWrite)
	if err != nil {
		return Result{}, err
	}
	if !d.present["secrets.json"] {
		if len(d.present) != 0 {
			return Result{}, ErrState
		}
		var entropy [64]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return Result{}, ErrState
		}
		defer clear(entropy[:])
		state := protocolJournal{Version: 1, Installation: foundation.Installation, Foundation: hex.EncodeToString(digest[:]),
			Windows: base64.StdEncoding.EncodeToString(entropy[:32]), Bootstrap: base64.StdEncoding.EncodeToString(entropy[32:])}
		encoded, err := json.Marshal(state)
		defer clear(encoded)
		if err != nil {
			return Result{}, ErrState
		}
		if err := d.write("secrets.json", encoded); err != nil {
			return Result{}, err
		}
	}
	encoded, err := d.read("secrets.json", 2048)
	if err != nil {
		return Result{}, err
	}
	defer clear(encoded)
	var state protocolJournal
	if json.Unmarshal(encoded, &state) != nil || state.Version != 1 || state.Installation != foundation.Installation || state.Foundation != hex.EncodeToString(digest[:]) {
		return Result{}, ErrState
	}
	canonical, err := json.Marshal(state)
	defer clear(canonical)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return Result{}, ErrState
	}
	windows, err := decodeProtocolSecret(state.Windows)
	defer clear(windows)
	if err != nil {
		return Result{}, err
	}
	seed, err := decodeProtocolSecret(state.Bootstrap)
	defer clear(seed)
	if err != nil || bytes.Equal(windows, seed) {
		return Result{}, ErrState
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	der, err := x509.MarshalPKCS8PrivateKey(private)
	defer clear(der)
	if err != nil {
		return Result{}, ErrState
	}
	values := [][]byte{[]byte(state.Windows), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}
	defer func() {
		for _, value := range values {
			clear(value)
		}
	}()
	marker := manifest{Version: 1, Installation: foundation.Installation, Files: map[string]string{}}
	for i, name := range protocolArtifacts {
		if !d.present[name] {
			if d.present["manifest.json"] {
				return Result{}, ErrState
			}
			if err := d.write(name, values[i]); err != nil {
				return Result{}, err
			}
		}
		actual, err := d.read(name, 512)
		equal := bytes.Equal(actual, values[i])
		clear(actual)
		if err != nil || !equal {
			return Result{}, ErrState
		}
		hash := sha256.Sum256(values[i])
		marker.Files[name] = hex.EncodeToString(hash[:])
	}
	verifyFoundation := func() error {
		current, currentDigest, err := provisionInstallation(ctx, installation, nil, false)
		if err != nil || current != foundation || currentDigest != digest {
			return ErrState
		}
		return nil
	}
	if err := verifyFoundation(); err != nil {
		return Result{}, err
	}
	data, err := json.Marshal(marker)
	if err != nil {
		return Result{}, ErrState
	}
	if d.present["manifest.json"] {
		actual, err := d.read("manifest.json", 2048)
		if err != nil || !bytes.Equal(data, actual) {
			return Result{}, ErrState
		}
	} else if err := d.write("manifest.json", data); err != nil {
		return Result{}, err
	}
	if err := verifyFoundation(); err != nil {
		return Result{}, err
	}
	if err := d.check(); err != nil {
		return Result{}, err
	}
	return foundation, nil
}

func decodeProtocolSecret(encoded string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, ErrState
	}
	return decoded, nil
}

// Resolve ancestor aliases before creating anything. The source and destination
// may not contain one another, even through a symbolic link in a trusted parent.
func separateDirectories(destination, source string) bool {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return false
	}
	source, err := filepath.EvalSymlinks(source)
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(destination)
	if err != nil {
		parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
		if err != nil {
			return false
		}
		resolved = filepath.Join(parent, filepath.Base(destination))
	}
	contains := func(parent, child string) bool {
		relative, err := filepath.Rel(parent, child)
		return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
	}
	if contains(source, resolved) || contains(resolved, source) {
		return false
	}
	// Separate container mount paths can name the same underlying directory.
	// Comparing names alone would permit a writable alias of the read-only
	// foundation to receive new output before the final source check failed.
	for _, pair := range [][2]string{{source, resolved}, {resolved, source}} {
		identity, err := os.Stat(pair[0])
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false
		}
		for path := pair[1]; ; path = filepath.Dir(path) {
			current, err := os.Stat(path)
			if err != nil && !os.IsNotExist(err) || err == nil && os.SameFile(identity, current) {
				return false
			}
			if path == filepath.Dir(path) {
				break
			}
		}
	}
	return true
}
