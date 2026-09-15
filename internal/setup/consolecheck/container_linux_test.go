//go:build linux

package consolecheck

import (
	"crypto/x509"
	"database/sql"
	"debug/buildinfo"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestConsoleContainerRuntime(t *testing.T) {
	if os.Getenv("OPENUEM_CONSOLE_CONTAINER_TEST") != "1" {
		t.Skip("requires the dedicated console smoke image")
	}
	if os.Geteuid() == 0 {
		t.Fatal("console runtime test must not run as root")
	}
	info, err := buildinfo.ReadFile("/openuem-console")
	if err != nil {
		t.Fatal("console executable has no readable build metadata")
	}
	cgo := false
	for _, setting := range info.Settings {
		if setting.Key == "CGO_ENABLED" && setting.Value == "1" {
			cgo = true
		}
	}
	if !cgo {
		t.Fatal("console executable cannot retain the SQLite package catalog implementation")
	}
	// Exercise the SQLite driver against the distribution's C runtime. The real
	// console uses this driver to import the downloaded Windows package catalog.
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "packages.db"))
	if err != nil {
		t.Fatal("SQLite is unavailable in the console runtime")
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE packages(id TEXT PRIMARY KEY, name TEXT NOT NULL);
	 INSERT INTO packages VALUES('fixture.application','Fixture Application')`); err != nil {
		t.Fatal("runtime SQLite catalog creation failed")
	}
	var id, name string
	if err := db.QueryRow(`SELECT DISTINCT id,name FROM packages`).Scan(&id, &name); err != nil || id != "fixture.application" || name != "Fixture Application" {
		t.Fatal("runtime SQLite catalog query failed")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || len(roots.Subjects()) == 0 {
		t.Fatal("runtime has no public TLS trust")
	}
	command := exec.CommandContext(t.Context(), "/openuem-console", "--help")
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "openuem-console") {
		t.Fatal("actual console executable cannot start in its distribution image")
	}
}
