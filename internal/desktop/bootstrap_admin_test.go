package desktop

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/keyfile"
)

func TestBootstrapSigningKeyInitializationRetainsKeyAndOnlyReportsPublicMetadata(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "signer")
	var output bytes.Buffer
	if err := InitBootstrapKey(directory, &output); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, BootstrapKeyFilename)
	key, err := LoadBootstrapKey(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	var result struct {
		KeyID   string `json:"key_id"`
		Created bool   `json:"created"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || !result.Created || result.KeyID != artifacts.KeyID(key.Public().(ed25519.PublicKey)) {
		t.Fatal("invalid initialization metadata", err)
	}
	for _, secret := range []string{"PRIVATE KEY", path, base64.RawStdEncoding.EncodeToString(key[:ed25519.SeedSize])} {
		if strings.Contains(output.String(), secret) {
			t.Fatal("initialization exposed key or path")
		}
	}
	output.Reset()
	if err := InitBootstrapKey(directory, &output); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.Created || result.KeyID != artifacts.KeyID(key.Public().(ed25519.PublicKey)) {
		t.Fatal("restart replaced the signer", err)
	}
	if err := InitBootstrapKey(directory, bootstrapFailedWriter{}); err == nil {
		t.Fatal("ignored output failure")
	}
	retained, err := LoadBootstrapKey(path)
	if err != nil || !bytes.Equal(retained, key) {
		t.Fatal("output failure replaced or removed the key", err)
	}
	clear(retained)
}

type bootstrapFailedWriter struct{}

func (bootstrapFailedWriter) Write([]byte) (int, error) {
	return 0, errors.New("fixture output failed")
}

func TestBootstrapSigningKeyInitializationRejectsUnsafeOrPartialStateWithoutChanges(t *testing.T) {
	for _, directory := range []string{"", "relative", filepath.Join(t.TempDir(), "a") + string(filepath.Separator) + ".."} {
		if err := InitBootstrapKey(directory, io.Discard); err == nil {
			t.Fatal("accepted noncanonical directory")
		}
	}
	directory := filepath.Join(t.TempDir(), "no-output")
	if err := InitBootstrapKey(directory, nil); err == nil {
		t.Fatal("accepted missing output")
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid request created a directory")
	}
	for _, kind := range []string{"partial", "directory", "symlink", "shared"} {
		t.Run(kind, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "signer")
			if err := keyfile.CreateDirectory(directory); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, BootstrapKeyFilename)
			switch kind {
			case "partial":
				if err := keyfile.Create(path, []byte("-----BEGIN PRIVATE KEY-----\npartial")); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := keyfile.CreateDirectory(path); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if runtime.GOOS == "windows" {
					t.Skip("unprivileged symlink creation is unavailable")
				}
				if err := os.Symlink(filepath.Join(directory, "missing-target"), path); err != nil {
					t.Fatal(err)
				}
			case "shared":
				if runtime.GOOS == "windows" {
					t.Skip("native keyfile ACL tests cover shared Windows files")
				}
				if err := InitBootstrapKey(directory, io.Discard); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			original, _ := os.ReadFile(path)
			defer clear(original)
			if err := InitBootstrapKey(directory, io.Discard); !errors.Is(err, ErrBootstrapConfiguration) {
				t.Fatal("unsafe state was accepted", err)
			}
			after, err := os.Lstat(path)
			current, _ := os.ReadFile(path)
			defer clear(current)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || !bytes.Equal(original, current) {
				t.Fatal("unsafe state was silently repaired or replaced", err)
			}
		})
	}
}

func TestBootstrapSigningKeyInitializationConcurrentWritersNeverReplaceTheWinner(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "signer")
	if err := keyfile.CreateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	results := make(chan string, 8)
	for range 8 {
		group.Go(func() {
			var output bytes.Buffer
			if err := InitBootstrapKey(directory, &output); err != nil {
				return
			}
			var result struct {
				KeyID string `json:"key_id"`
			}
			if err := json.Unmarshal(output.Bytes(), &result); err != nil {
				t.Error(err)
				return
			}
			results <- result.KeyID
		})
	}
	group.Wait()
	close(results)
	key, err := LoadBootstrapKey(filepath.Join(directory, BootstrapKeyFilename))
	if err != nil {
		t.Fatal("no complete winner", err)
	}
	defer clear(key)
	winner := artifacts.KeyID(key.Public().(ed25519.PublicKey))
	count := 0
	for result := range results {
		count++
		if result != winner {
			t.Fatal("concurrent initialization returned a different key")
		}
	}
	if count == 0 {
		t.Fatal("no initialization completed")
	}
	if err := InitBootstrapKey(directory, io.Discard); err != nil {
		t.Fatal("completed winner could not be reopened", err)
	}
}
