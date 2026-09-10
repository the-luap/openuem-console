package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const (
	JWTFile      = "jwt.key"
	MasterFile   = "encryption.key"
	PasswordFile = "initial-password"
)

var artifacts = []string{JWTFile, MasterFile, PasswordFile}

type journal struct {
	Version      int    `json:"version"`
	Installation string `json:"installation"`
	JWT          string `json:"jwt"`
	Master       string `json:"master"`
	Password     string `json:"password"`
}

// Result contains public metadata only. It never carries secret material.
type Result struct {
	Installation string `json:"installation"`
}

type manifest struct {
	Version      int               `json:"version"`
	Installation string            `json:"installation"`
	Files        map[string]string `json:"files"`
}

// Initialize creates or verifies a private provisioning directory on Linux or
// macOS. The durable journal is written before any mountable file. Complete
// writes can be resumed with exactly the same credentials. Existing incomplete,
// invalid or changed files are never overwritten, repaired or rotated. Consumers
// may start only after this command succeeds. Keep the parent directory trusted.
func Initialize(ctx context.Context, path string) (Result, error) {
	return initialize(ctx, path, nil)
}

func initialize(ctx context.Context, path string, afterWrite func(string) error) (Result, error) {
	result, _, err := provisionInstallation(ctx, path, afterWrite, true)
	return result, err
}

// The read-only mode verifies an already completed foundation without creating
// directories, resuming interrupted exports or repairing missing files.
func provisionInstallation(ctx context.Context, path string, afterWrite func(string) error, create bool) (Result, [32]byte, error) {
	d, err := provisioning(ctx, path, append([]string{"secrets.json", "manifest.json"}, artifacts...), afterWrite, create)
	if err != nil {
		return Result{}, [32]byte{}, err
	}
	present := d.present
	if !present["secrets.json"] {
		if !create || len(present) != 0 {
			return Result{}, [32]byte{}, ErrState
		}
		state, err := generate()
		if err != nil {
			return Result{}, [32]byte{}, err
		}
		encoded, err := json.Marshal(state)
		if err != nil {
			return Result{}, [32]byte{}, ErrState
		}
		defer clear(encoded)
		if err := d.write("secrets.json", encoded); err != nil {
			return Result{}, [32]byte{}, err
		}
	}
	encoded, err := d.read("secrets.json", 2048)
	if err != nil {
		return Result{}, [32]byte{}, err
	}
	defer clear(encoded)
	var state journal
	if json.Unmarshal(encoded, &state) != nil || !valid(state) {
		return Result{}, [32]byte{}, ErrState
	}
	canonical, err := json.Marshal(state)
	defer clear(canonical)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return Result{}, [32]byte{}, ErrState
	}
	values := []string{state.JWT, state.Master, state.Password}
	marker := manifest{Version: 1, Installation: state.Installation, Files: map[string]string{}}
	for index, name := range artifacts {
		if err := d.check(); err != nil {
			return Result{}, [32]byte{}, err
		}
		value := []byte(values[index])
		if !present[name] {
			if !create || present["manifest.json"] {
				clear(value)
				return Result{}, [32]byte{}, ErrState
			}
			if err := d.write(name, value); err != nil {
				clear(value)
				return Result{}, [32]byte{}, err
			}
		}
		actual, err := d.read(name, 128)
		equal := bytes.Equal(value, actual)
		clear(actual)
		digest := sha256.Sum256(value)
		clear(value)
		if err != nil || !equal {
			return Result{}, [32]byte{}, ErrState
		}
		marker.Files[name] = hex.EncodeToString(digest[:])
	}
	data, err := json.Marshal(marker)
	if err != nil {
		return Result{}, [32]byte{}, ErrState
	}
	if present["manifest.json"] {
		actual, err := d.read("manifest.json", 2048)
		if err != nil || !bytes.Equal(data, actual) {
			return Result{}, [32]byte{}, ErrState
		}
	} else if !create {
		return Result{}, [32]byte{}, ErrState
	} else if err := d.write("manifest.json", data); err != nil {
		return Result{}, [32]byte{}, err
	}
	if err := d.check(); err != nil {
		return Result{}, [32]byte{}, err
	}
	return Result{Installation: state.Installation}, sha256.Sum256(data), nil
}

func generate() (journal, error) {
	var raw [104]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return journal{}, errors.New("installation secret generation failed")
	}
	defer clear(raw[:])
	return journal{Version: 1, Installation: hex.EncodeToString(raw[:16]), JWT: base64.RawURLEncoding.EncodeToString(raw[16:48]), Master: base64.RawURLEncoding.EncodeToString(raw[48:72]), Password: "Aa0!" + base64.RawURLEncoding.EncodeToString(raw[72:])}, nil
}

func valid(state journal) bool {
	id, err := hex.DecodeString(state.Installation)
	if err != nil || len(id) != 16 || state.Version != 1 || hex.EncodeToString(id) != state.Installation || len(state.Password) != 47 || state.Password[:4] != "Aa0!" {
		return false
	}
	for index, value := range []string{state.JWT, state.Master, state.Password[4:]} {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
		length := 32
		if index == 1 {
			length = 24
		}
		valid := err == nil && len(decoded) == length && base64.RawURLEncoding.EncodeToString(decoded) == value
		clear(decoded)
		if !valid {
			return false
		}
	}
	return state.JWT != state.Password[4:]
}
