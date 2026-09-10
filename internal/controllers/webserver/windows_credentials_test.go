package webserver

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment/keyfile"
)

func TestIndividualWindowsProtectedMasterKey(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("w", 32)))
	path := filepath.Join(t.TempDir(), "windows.key")
	if err := keyfile.Create(path, []byte(encoded+"\r\n")); err != nil {
		t.Fatal("cannot create protected Windows master-key fixture")
	}
	values := map[string]string{"WINDOWS_MDM_LISTEN_ADDR": "127.0.0.1:0", "WINDOWS_MDM_MASTER_KEY_FILE": path}
	get := func(name string) string { return values[name] }
	config, err := windowsConfiguration("https://uem.example.test", "certificate", "key", get)
	if err != nil || config.masterKey != encoded {
		t.Fatal("protected Windows key did not reach listener configuration")
	}
	values["WINDOWS_MDM_MASTER_KEY"] = encoded
	if config, err := windowsConfiguration("https://uem.example.test", "certificate", "key", get); err == nil || config != nil || strings.Contains(err.Error(), encoded) {
		t.Fatal("ambiguous Windows key sources were accepted or exposed")
	}
	delete(values, "WINDOWS_MDM_MASTER_KEY")
	values["WINDOWS_MDM_MASTER_KEY_FILE"] = path + ".missing"
	if config, err := windowsConfiguration("https://uem.example.test", "certificate", "key", get); err == nil || config != nil {
		t.Fatal("missing Windows key file did not fail startup")
	}
	for _, data := range []string{encoded + "\n\n", " " + encoded, strings.TrimSuffix(encoded, "="), encoded + strings.Repeat("x", 100), "invalid"} {
		invalid := filepath.Join(t.TempDir(), "invalid.key")
		if keyfile.Create(invalid, []byte(data)) != nil {
			t.Fatal("cannot create invalid protected fixture")
		}
		if value, err := windowsMasterKey("", invalid); err == nil || value != "" {
			t.Fatal("malformed Windows key file was accepted")
		}
	}
	if runtime.GOOS != "windows" {
		if os.Chmod(path, 0644) != nil {
			t.Fatal("cannot change fixture permissions")
		}
		if value, err := windowsMasterKey("", path); err == nil || value != "" {
			t.Fatal("public Windows master-key file was accepted")
		}
	}
}
