//go:build linux || darwin

package secrets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func protocolFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	installation, output := filepath.Join(root, "installation"), filepath.Join(root, "protocol")
	if _, err := Initialize(t.Context(), installation); err != nil {
		t.Fatal(err)
	}
	return installation, output
}

func protocolSnapshot(t *testing.T, directory string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				t.Fatal(err)
			}
			result[entry.Name()] = info.Mode().String() + target
		} else {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(data)
			clear(data)
			result[entry.Name()] = info.Mode().String() + hex.EncodeToString(hash[:])
		}
	}
	return result
}

func TestInstallationSecretsProtocolKeys(t *testing.T) {
	installation, output := protocolFixture(t)
	source := protocolSnapshot(t, installation)
	result, err := InitializeProtocolKeys(t.Context(), output, installation)
	if err != nil {
		t.Fatal(err)
	}
	before := protocolSnapshot(t, output)
	if len(before) != 4 {
		t.Fatal("unexpected protocol key inventory")
	}
	for _, directory := range []string{installation, output} {
		info, err := os.Stat(directory)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("output directory is not private")
		}
		entries, _ := os.ReadDir(directory)
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				t.Fatal("output file is not private")
			}
		}
	}
	raw, _ := os.ReadFile(filepath.Join(output, WindowsKeyFile))
	windows, err := base64.StdEncoding.Strict().DecodeString(string(raw))
	if err != nil || len(windows) != 32 || len(raw) != 44 {
		t.Fatal("invalid Windows key encoding")
	}
	block, err := aes.NewCipher(windows)
	if err != nil {
		t.Fatal(err)
	}
	box, _ := cipher.NewGCM(block)
	nonce := make([]byte, box.NonceSize())
	sealed := box.Seal(nil, nonce, []byte("synthetic authority"), nil)
	plain, err := box.Open(nil, nonce, sealed, nil)
	if err != nil || string(plain) != "synthetic authority" {
		t.Fatal("Windows encryption round trip failed")
	}
	data, _ := os.ReadFile(filepath.Join(output, DesktopBootstrapKeyFile))
	pemBlock, rest := pem.Decode(data)
	if pemBlock == nil || pemBlock.Type != "PRIVATE KEY" || len(rest) != 0 {
		t.Fatal("invalid desktop key export")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || bytes.Equal(key.Seed(), windows) {
		t.Fatal("protocol keys are not independent")
	}
	message := []byte("synthetic bootstrap configuration")
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), message, ed25519.Sign(key, message)) {
		t.Fatal("bootstrap signature failed")
	}
	for range 2 {
		again, err := InitializeProtocolKeys(t.Context(), output, installation)
		if err != nil || again != result || !reflect.DeepEqual(before, protocolSnapshot(t, output)) {
			t.Fatal("retry changed keys", err)
		}
	}
	if !reflect.DeepEqual(source, protocolSnapshot(t, installation)) {
		t.Fatal("source installation was changed")
	}
	otherSource, otherOutput := protocolFixture(t)
	if _, err := InitializeProtocolKeys(t.Context(), otherOutput, otherSource); err != nil {
		t.Fatal(err)
	}
	other, _ := os.ReadFile(filepath.Join(otherOutput, WindowsKeyFile))
	otherBootstrap, _ := os.ReadFile(filepath.Join(otherOutput, DesktopBootstrapKeyFile))
	if bytes.Equal(raw, other) || bytes.Equal(data, otherBootstrap) {
		t.Fatal("separate installations reused keys")
	}
}

func TestInstallationSecretsProtocolInterrupted(t *testing.T) {
	for _, stop := range []string{"secrets.json", WindowsKeyFile, DesktopBootstrapKeyFile, "manifest.json"} {
		t.Run(stop, func(t *testing.T) {
			installation, output := protocolFixture(t)
			interrupted := errors.New("synthetic interruption")
			_, err := initializeProtocolKeys(t.Context(), output, installation, func(name string) error {
				if name == stop {
					return interrupted
				}
				return nil
			})
			if !errors.Is(err, interrupted) {
				t.Fatal("interruption not reached", err)
			}
			before := protocolSnapshot(t, output)
			if _, err := InitializeProtocolKeys(t.Context(), output, installation); err != nil {
				t.Fatal("could not resume completed writes", err)
			}
			after := protocolSnapshot(t, output)
			for name, value := range before {
				if after[name] != value {
					t.Fatal("resume replaced retained material")
				}
			}
		})
	}
}

func TestInstallationSecretsProtocolRejectDamage(t *testing.T) {
	for _, kind := range []string{"missing journal", "partial journal", "unknown JSON", "duplicate JSON", "same keys", "bad encoding", "missing Windows", "missing bootstrap", "changed key", "changed manifest", "extra file", "symlink", "file permissions", "directory permissions"} {
		t.Run(kind, func(t *testing.T) {
			installation, output := protocolFixture(t)
			if _, err := InitializeProtocolKeys(t.Context(), output, installation); err != nil {
				t.Fatal(err)
			}
			write := func(name string, data []byte) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			remove := func(name string) {
				t.Helper()
				if err := os.Remove(filepath.Join(output, name)); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "missing journal":
				remove("secrets.json")
			case "partial journal":
				write("secrets.json", []byte(`{"version":`))
			case "unknown JSON", "duplicate JSON":
				data, _ := os.ReadFile(filepath.Join(output, "secrets.json"))
				prefix := `{"unknown":1,`
				if kind == "duplicate JSON" {
					prefix = `{"version":1,`
				}
				write("secrets.json", append([]byte(prefix), data[1:]...))
			case "same keys", "bad encoding":
				data, _ := os.ReadFile(filepath.Join(output, "secrets.json"))
				var state protocolJournal
				if json.Unmarshal(data, &state) != nil {
					t.Fatal("invalid fixture journal")
				}
				state.Bootstrap = state.Windows
				if kind == "bad encoding" {
					state.Windows += "\n"
				}
				data, _ = json.Marshal(state)
				write("secrets.json", data)
			case "missing Windows":
				remove(WindowsKeyFile)
			case "missing bootstrap":
				remove(DesktopBootstrapKeyFile)
			case "changed key":
				write(WindowsKeyFile, bytes.Repeat([]byte("a"), 44))
			case "changed manifest":
				write("manifest.json", []byte(`{}`))
			case "extra file":
				write("unrelated", []byte("retained"))
			case "symlink":
				remove(WindowsKeyFile)
				if err := os.Symlink(filepath.Join(installation, MasterFile), filepath.Join(output, WindowsKeyFile)); err != nil {
					t.Fatal(err)
				}
			case "file permissions":
				if err := os.Chmod(filepath.Join(output, WindowsKeyFile), 0644); err != nil {
					t.Fatal(err)
				}
			case "directory permissions":
				if err := os.Chmod(output, 0755); err != nil {
					t.Fatal(err)
				}
			}
			before := protocolSnapshot(t, output)
			if _, err := InitializeProtocolKeys(t.Context(), output, installation); !errors.Is(err, ErrState) {
				t.Fatal("damaged state accepted", err)
			}
			if !reflect.DeepEqual(before, protocolSnapshot(t, output)) {
				t.Fatal("rejection modified damaged files")
			}
		})
	}
}

func TestInstallationSecretsProtocolFoundation(t *testing.T) {
	for _, missing := range []string{"directory", "secrets.json", JWTFile, MasterFile, PasswordFile, "manifest.json"} {
		t.Run(missing, func(t *testing.T) {
			installation, output := protocolFixture(t)
			if missing == "directory" {
				installation += "-absent"
			} else if err := os.Remove(filepath.Join(installation, missing)); err != nil {
				t.Fatal(err)
			}
			var before map[string]string
			if missing != "directory" {
				before = protocolSnapshot(t, installation)
			}
			if _, err := InitializeProtocolKeys(t.Context(), output, installation); err == nil {
				t.Fatal("incomplete foundation accepted")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatal("invalid source created output")
			}
			if missing == "directory" {
				if _, err := os.Lstat(installation); !os.IsNotExist(err) {
					t.Fatal("missing source was created")
				}
			} else if !reflect.DeepEqual(before, protocolSnapshot(t, installation)) {
				t.Fatal("source was repaired")
			}
		})
	}
	installation, output := protocolFixture(t)
	if _, err := InitializeProtocolKeys(t.Context(), output, installation); err != nil {
		t.Fatal(err)
	}
	before := protocolSnapshot(t, output)
	other, _ := protocolFixture(t)
	if _, err := InitializeProtocolKeys(t.Context(), output, other); err == nil {
		t.Fatal("another installation accepted")
	}
	// A coherent replacement of the foundation with the same public installation
	// ID must also fail: the binding includes the original credential manifest.
	data, _ := os.ReadFile(filepath.Join(installation, "secrets.json"))
	var state journal
	if json.Unmarshal(data, &state) != nil {
		t.Fatal("invalid fixture source")
	}
	replacement, _ := generate()
	replacement.Installation = state.Installation
	data, _ = json.Marshal(replacement)
	if err := os.WriteFile(filepath.Join(installation, "secrets.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range append([]string{"manifest.json"}, artifacts...) {
		if err := os.Remove(filepath.Join(installation, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Initialize(t.Context(), installation); err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeProtocolKeys(t.Context(), output, installation); err == nil {
		t.Fatal("changed foundation with retained ID accepted")
	}
	if !reflect.DeepEqual(before, protocolSnapshot(t, output)) {
		t.Fatal("binding rejection modified keys")
	}
}

func TestInstallationSecretsProtocolPathsAndCancellation(t *testing.T) {
	installation, output := protocolFixture(t)
	source := protocolSnapshot(t, installation)
	alias := filepath.Join(filepath.Dir(installation), "alias")
	if err := os.Symlink(installation, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{installation, filepath.Join(installation, "nested"), filepath.Dir(installation), filepath.Join(alias, "nested"), "relative"} {
		if _, err := InitializeProtocolKeys(t.Context(), path, installation); err == nil {
			t.Fatal("overlapping or relative output accepted")
		}
	}
	if !reflect.DeepEqual(source, protocolSnapshot(t, installation)) {
		t.Fatal("path rejection modified source")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := InitializeProtocolKeys(ctx, output, installation); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled operation proceeded", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("cancellation created output")
	}
}

func TestInstallationSecretsProtocolConcurrentAndSourceMutation(t *testing.T) {
	installation, output := protocolFixture(t)
	var group sync.WaitGroup
	for range 6 {
		group.Go(func() {
			if _, err := InitializeProtocolKeys(t.Context(), output, installation); err != nil && !errors.Is(err, ErrState) {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if _, err := InitializeProtocolKeys(t.Context(), output, installation); err != nil {
		t.Fatal("concurrent creation corrupted retained keys", err)
	}
	for _, stop := range []string{WindowsKeyFile, "manifest.json"} {
		t.Run(stop, func(t *testing.T) {
			source, destination := protocolFixture(t)
			_, err := initializeProtocolKeys(t.Context(), destination, source, func(name string) error {
				if name == stop {
					return os.Remove(filepath.Join(source, JWTFile))
				}
				return nil
			})
			if !errors.Is(err, ErrState) {
				t.Fatal("foundation changed during output creation without rejection", err)
			}
			before := protocolSnapshot(t, destination)
			if _, err := InitializeProtocolKeys(t.Context(), destination, source); err == nil {
				t.Fatal("damaged foundation accepted on retry")
			}
			if !reflect.DeepEqual(before, protocolSnapshot(t, destination)) {
				t.Fatal("retry changed retained output")
			}
		})
	}
}

func TestInstallationSecretsProtocolReadOnlyFoundationAndMarkerRecovery(t *testing.T) {
	installation, output := protocolFixture(t)
	for _, name := range append([]string{"secrets.json", "manifest.json"}, artifacts...) {
		if err := os.Chmod(filepath.Join(installation, name), 0400); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(installation, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(installation, 0700) })
	source := protocolSnapshot(t, installation)
	if _, err := InitializeProtocolKeys(t.Context(), output, installation); err != nil {
		t.Fatal("read-only foundation rejected", err)
	}
	before := protocolSnapshot(t, output)
	if err := os.Remove(filepath.Join(output, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeProtocolKeys(t.Context(), output, installation); err != nil {
		t.Fatal("marker recovery rejected", err)
	}
	if !reflect.DeepEqual(before, protocolSnapshot(t, output)) || !reflect.DeepEqual(source, protocolSnapshot(t, installation)) {
		t.Fatal("marker recovery changed retained credentials")
	}
}
