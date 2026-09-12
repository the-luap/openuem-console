package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment/keyfile"
)

func privateFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential")
	if err := keyfile.Create(path, []byte(value)); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInstallationSecretsLoad(t *testing.T) {
	jwt, master := strings.Repeat("j", 43), strings.Repeat("m", 32)
	for _, ending := range []string{"", "\n", "\r\n"} {
		result, err := Load(Inputs{JWTFile: privateFile(t, jwt+ending), MasterFile: privateFile(t, master+ending), Required: true})
		if err != nil || result.JWT != jwt || result.Master != master {
			t.Fatal("protected file contents were not loaded exactly", err)
		}
	}
	if _, err := Load(Inputs{JWT: "legacy"}); err != nil {
		t.Fatal("legacy raw JWT changed", err)
	}
	for _, input := range []Inputs{
		{}, {JWT: "short", Master: master, Required: true}, {JWT: jwt, Required: true},
		{JWT: jwt, Master: master, Installation: "invalid"},
		{JWT: jwt, Master: master, Installation: strings.Repeat("A", 32)},
		{JWT: jwt, Installation: strings.Repeat("a", 32)},
		{JWT: jwt, Master: strings.Repeat("m", 64), Required: true},
		{JWT: jwt, JWTFile: privateFile(t, jwt)},
		{JWT: jwt, Master: master, MasterFile: privateFile(t, master)},
		{JWT: jwt, MasterFile: filepath.Join(t.TempDir(), "missing")},
	} {
		result, err := Load(input)
		if !errors.Is(err, ErrConfiguration) || result != (Runtime{}) {
			t.Fatal("invalid/ambiguous configuration returned credentials")
		}
		if strings.Contains(err.Error(), jwt) || strings.Contains(err.Error(), master) {
			t.Fatal("credential leaked in error")
		}
	}
	if value, err := Load(Inputs{Installation: strings.Repeat("a", 32), JWT: jwt, Master: master}); err != nil || value.Installation != strings.Repeat("a", 32) {
		t.Fatal("installation binding identity was not retained", err)
	}
}

func TestInstallationSecretsFileBoundaries(t *testing.T) {
	for name, content := range map[string]string{
		"short": strings.Repeat("a", 31), "long": strings.Repeat("a", 129),
		"bare CR": strings.Repeat("a", 32) + "\r", "two lines": strings.Repeat("a", 32) + "\n\n",
		"space": strings.Repeat("a", 32) + " ", "NUL": strings.Repeat("a", 32) + "\x00",
		"Unicode": strings.Repeat("a", 32) + "é", "oversized": strings.Repeat("a", 4096),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(Inputs{JWTFile: privateFile(t, content)}); !errors.Is(err, ErrConfiguration) {
				t.Fatal("invalid file accepted")
			}
		})
	}
	if _, err := Load(Inputs{JWT: strings.Repeat("j", 43), MasterFile: privateFile(t, strings.Repeat("m", 33))}); err == nil {
		t.Fatal("encoded/oversized master key accepted")
	}
	if _, err := Load(Inputs{JWTFile: t.TempDir()}); err == nil {
		t.Fatal("directory accepted")
	}
	if runtime.GOOS != "windows" {
		original := privateFile(t, strings.Repeat("j", 43))
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(original, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(Inputs{JWTFile: link}); err == nil {
			t.Fatal("symbolic link accepted")
		}
		if err := os.Chmod(original, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(Inputs{JWTFile: original}); err == nil {
			t.Fatal("shared file accepted")
		}
	}
}
