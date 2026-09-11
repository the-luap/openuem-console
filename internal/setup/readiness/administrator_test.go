package readiness

import (
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReferenceReadinessAdministratorInputs(t *testing.T) {
	directory := t.TempDir()
	public, _, _ := identity(t)
	trust := write(t, directory, "ca.pem", public)
	valid := Options{Mode: "administrator", Installation: strings.Repeat("1", 32), Administrator: "first-admin",
		InitialPasswordFile: write(t, directory, "initial", []byte(strings.Repeat("p", 43))),
		JWTFile:             write(t, directory, "jwt", []byte(strings.Repeat("j", 43))),
		MasterFile:          write(t, directory, "master", []byte(strings.Repeat("m", 32)))}
	connection := "postgres://console:synthetic-secret@127.0.0.1:5432/openuem?sslmode=verify-full&sslrootcert=" + url.QueryEscape(trust)
	valid.DatabaseURLFile = write(t, directory, "database.url", []byte(connection))
	// Constructing a valid check must perform no database I/O. Actual readiness
	// and password replacement are exercised in the isolated reference project.
	check, close, err := administratorCheck(deadline(t, time.Second), valid)
	if err != nil || check == nil || close == nil {
		t.Fatal("valid protected administrator inputs were rejected", err)
	}
	close()
	for _, suffix := range []string{"&sslmode=disable", "&host=other.invalid", "&search_path=other", "&options=-c+search_path%3Dother", "&sslrootcert=" + url.QueryEscape(trust)} {
		options := valid
		options.DatabaseURLFile = write(t, t.TempDir(), "invalid.url", []byte(connection+suffix))
		if _, _, err := administratorCheck(deadline(t, time.Second), options); !errors.Is(err, ErrConfiguration) || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("ambiguous or redirected database options were accepted or echoed")
		}
	}
	for _, change := range []func(*Options){
		func(o *Options) { o.Mode = "http" },
		func(o *Options) { o.Address = "http://127.0.0.1:8000/healthz" },
		func(o *Options) { o.KeyFile = valid.JWTFile },
		func(o *Options) { o.InitialPasswordFile = "relative" },
		func(o *Options) { o.Installation = "invalid" },
		func(o *Options) { o.Administrator = "../invalid" },
		func(o *Options) { o.JWTFile = filepath.Join(directory, "missing") },
	} {
		options := valid
		change(&options)
		if err := Wait(deadline(t, time.Second), options); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid or mixed administrator options were accepted", err)
		}
	}
}
