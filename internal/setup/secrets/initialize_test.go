//go:build linux || darwin

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/open-uem/utils"
)

func snapshot(t *testing.T, path string) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	for _, name := range append([]string{"secrets.json", "manifest.json"}, artifacts...) {
		data, err := os.ReadFile(filepath.Join(path, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		result[name] = data
	}
	return result
}

func same(t *testing.T, expected map[string][]byte, path string) {
	t.Helper()
	for name, value := range expected {
		actual, err := os.ReadFile(filepath.Join(path, name))
		if err != nil || !bytes.Equal(actual, value) {
			t.Fatal("existing credential changed", name, err)
		}
	}
}

func TestInstallationSecretsGenerateAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets")
	result, err := Initialize(context.Background(), path)
	if err != nil || len(result.Installation) != 32 {
		t.Fatal("generation failed", err)
	}
	original := snapshot(t, path)
	if len(original) != 5 {
		t.Fatal("missing committed secret files")
	}
	credentials, err := Load(Inputs{JWTFile: filepath.Join(path, JWTFile), MasterFile: filepath.Join(path, MasterFile), Required: true})
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the actual legacy AES API; an encoded 32-byte key would fail here.
	encrypted, err := utils.EncryptSensitiveField("synthetic installation value", credentials.Master)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		again, err := Initialize(context.Background(), path)
		if err != nil || again != result {
			t.Fatal("restart failed", err)
		}
		same(t, original, path)
	}
	decrypted, err := utils.DecryptSensitiveField(encrypted, credentials.Master)
	if err != nil || decrypted != "synthetic installation value" {
		t.Fatal("persisted encryption key unusable", err)
	}
	other, err := Initialize(context.Background(), filepath.Join(t.TempDir(), "secrets"))
	if err != nil || other.Installation == result.Installation {
		t.Fatal("installations reused their identity", err)
	}
}

func TestInstallationSecretsInterruptedWrites(t *testing.T) {
	for _, stop := range append([]string{"secrets.json"}, append(artifacts, "manifest.json")...) {
		t.Run(stop, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secrets")
			interrupted := errors.New("synthetic interrupted provisioner")
			_, err := initialize(context.Background(), path, func(name string) error {
				if name == stop {
					return interrupted
				}
				return nil
			})
			if !errors.Is(err, interrupted) {
				t.Fatal("interruption not exercised", err)
			}
			original := snapshot(t, path)
			if _, err := Initialize(context.Background(), path); err != nil {
				t.Fatal("exact recovery failed", err)
			}
			same(t, original, path)
		})
	}
}

func TestInstallationSecretsRejectDamagedState(t *testing.T) {
	for _, kind := range []string{"missing journal", "partial journal", "unknown JSON", "duplicate JSON", "missing JWT", "changed master", "missing password", "changed manifest", "extra file", "symlink", "permissions", "directory permissions"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secrets")
			if _, err := Initialize(context.Background(), path); err != nil {
				t.Fatal(err)
			}
			mutate := func(name string, value []byte) {
				if err := os.WriteFile(filepath.Join(path, name), value, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "missing journal":
				if err := os.Remove(filepath.Join(path, "secrets.json")); err != nil {
					t.Fatal(err)
				}
			case "partial journal":
				mutate("secrets.json", []byte(`{"version":1`))
			case "unknown JSON", "duplicate JSON":
				data, err := os.ReadFile(filepath.Join(path, "secrets.json"))
				if err != nil {
					t.Fatal(err)
				}
				prefix := []byte(`{"unknown":true,`)
				if kind == "duplicate JSON" {
					prefix = []byte(`{"version":1,`)
				}
				mutate("secrets.json", append(prefix, data[1:]...))
			case "missing JWT":
				if err := os.Remove(filepath.Join(path, JWTFile)); err != nil {
					t.Fatal(err)
				}
			case "changed master":
				mutate(MasterFile, bytes.Repeat([]byte("m"), 32))
			case "missing password":
				if err := os.Remove(filepath.Join(path, PasswordFile)); err != nil {
					t.Fatal(err)
				}
			case "changed manifest":
				mutate("manifest.json", []byte(`{}`))
			case "extra file":
				mutate("unrelated", []byte("preserve"))
			case "symlink":
				if err := os.Remove(filepath.Join(path, JWTFile)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(path, MasterFile), filepath.Join(path, JWTFile)); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(filepath.Join(path, JWTFile), 0644); err != nil {
					t.Fatal(err)
				}
			case "directory permissions":
				if err := os.Chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
			}
			original := snapshot(t, path)
			if _, err := Initialize(context.Background(), path); !errors.Is(err, ErrState) {
				t.Fatal("damaged state accepted", err)
			}
			same(t, original, path)
		})
	}
}

func TestInstallationSecretsConcurrentAndCancelled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets")
	var wg sync.WaitGroup
	results := make(chan Result, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := Initialize(context.Background(), path)
			if err == nil {
				results <- result
			} else if !errors.Is(err, ErrState) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	close(results)
	final, err := Initialize(context.Background(), path)
	if err != nil {
		t.Fatal("concurrent provisioning corrupted state", err)
	}
	for result := range results {
		if result != final {
			t.Fatal("competing initialization returned another installation")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	missing := filepath.Join(t.TempDir(), "cancelled")
	if _, err := Initialize(ctx, missing); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled initialization proceeded", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled initialization wrote state")
	}
	if _, err := Initialize(context.Background(), "relative"); !errors.Is(err, ErrConfiguration) {
		t.Fatal("relative path accepted")
	}
	data, _ := json.Marshal(final)
	if bytes.Contains(data, []byte("master")) || bytes.Contains(data, []byte("password")) {
		t.Fatal("public result includes secrets")
	}
}
