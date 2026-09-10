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
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/open-uem/nats/enrollment/keyfile"
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
	if !supported() || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == filepath.Dir(path) {
		return Result{}, ErrConfiguration
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if keyfile.CreateDirectory(path) != nil {
		return Result{}, ErrState
	}
	if syncDirectory(filepath.Dir(path)) != nil {
		return Result{}, ErrState
	}
	identity, err := os.Lstat(path)
	if err != nil {
		return Result{}, ErrState
	}
	check := func() error {
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(identity, current) || keyfile.CheckDirectory(path) != nil {
			return ErrState
		}
		return ctx.Err()
	}
	if err := check(); err != nil {
		return Result{}, err
	}
	directory, err := os.Open(path)
	if err != nil {
		return Result{}, ErrState
	}
	entries, err := directory.ReadDir(6)
	directory.Close()
	if err != nil && err != io.EOF || len(entries) > 5 {
		return Result{}, ErrState
	}
	present := map[string]bool{}
	for _, entry := range entries {
		if !slices.Contains(artifacts, entry.Name()) && entry.Name() != "secrets.json" && entry.Name() != "manifest.json" {
			return Result{}, ErrState
		}
		present[entry.Name()] = true
	}
	write := func(name string, data []byte) error {
		if err := check(); err != nil {
			return err
		}
		if keyfile.Create(filepath.Join(path, name), data) != nil || syncDirectory(path) != nil {
			return ErrState
		}
		if afterWrite != nil {
			return afterWrite(name)
		}
		return nil
	}
	if !present["secrets.json"] {
		if len(present) != 0 {
			return Result{}, ErrState
		}
		state, err := generate()
		if err != nil {
			return Result{}, err
		}
		encoded, err := json.Marshal(state)
		if err != nil {
			return Result{}, ErrState
		}
		defer clear(encoded)
		if err := write("secrets.json", encoded); err != nil {
			return Result{}, err
		}
	}
	encoded, err := read(filepath.Join(path, "secrets.json"), 2048)
	if err != nil {
		return Result{}, err
	}
	defer clear(encoded)
	var state journal
	if json.Unmarshal(encoded, &state) != nil || !valid(state) {
		return Result{}, ErrState
	}
	canonical, err := json.Marshal(state)
	defer clear(canonical)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return Result{}, ErrState
	}
	values := []string{state.JWT, state.Master, state.Password}
	marker := manifest{Version: 1, Installation: state.Installation, Files: map[string]string{}}
	for index, name := range artifacts {
		if err := check(); err != nil {
			return Result{}, err
		}
		value := []byte(values[index])
		if !present[name] {
			if present["manifest.json"] {
				clear(value)
				return Result{}, ErrState
			}
			if err := write(name, value); err != nil {
				clear(value)
				return Result{}, err
			}
		}
		actual, err := read(filepath.Join(path, name), 128)
		equal := bytes.Equal(value, actual)
		clear(actual)
		digest := sha256.Sum256(value)
		clear(value)
		if err != nil || !equal {
			return Result{}, ErrState
		}
		marker.Files[name] = hex.EncodeToString(digest[:])
	}
	data, err := json.Marshal(marker)
	if err != nil {
		return Result{}, ErrState
	}
	if present["manifest.json"] {
		actual, err := read(filepath.Join(path, "manifest.json"), 2048)
		if err != nil || !bytes.Equal(data, actual) {
			return Result{}, ErrState
		}
	} else if err := write("manifest.json", data); err != nil {
		return Result{}, err
	}
	if err := check(); err != nil {
		return Result{}, err
	}
	return Result{Installation: state.Installation}, nil
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
