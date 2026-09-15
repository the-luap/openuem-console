package secrets

import (
	"errors"
	"strings"
	"testing"
)

func TestInstallationSecretsDatabaseURL(t *testing.T) {
	value := "postgres://console:synthetic%21password@db.internal:5432/openuem?sslmode=verify-full&sslrootcert=%2Frun%2Ftrust%2Fdatabase.pem"
	for _, ending := range []string{"", "\n", "\r\n"} {
		actual, err := DatabaseURL("", privateFile(t, value+ending))
		if err != nil || actual != value {
			t.Fatal("protected database URL changed", err)
		}
	}
	for _, raw := range []string{value, "host=/private/socket user=console dbname=openuem"} {
		actual, err := DatabaseURL(raw, "")
		if err != nil || actual != raw {
			t.Fatal("legacy database grammar changed", err)
		}
	}
	for _, input := range []string{
		"https://console:synthetic-password@db.internal/openuem",
		"postgres://db.internal", "postgres:///openuem", "postgres:opaque",
		"postgres://console:synthetic-password@db.internal/openuem#fragment",
		"postgres://console:synthetic-password@db.internal:invalid/openuem",
		"postgres://db.internal/openuem?sslmode=verify-full;unexpected=true",
		value + "\n\n", value + "\r", value + " ", value + "\x00", value + "é",
		strings.Repeat("p", 8195),
	} {
		actual, err := DatabaseURL("", privateFile(t, input))
		if !errors.Is(err, ErrConfiguration) || actual != "" {
			t.Fatal("invalid database input accepted")
		}
		if strings.Contains(err.Error(), "synthetic-password") || strings.Contains(err.Error(), input) {
			t.Fatal("database credential leaked")
		}
	}
	if _, err := DatabaseURL(value, privateFile(t, value)); !errors.Is(err, ErrConfiguration) {
		t.Fatal("ambiguous database input accepted", err)
	}
	if _, err := DatabaseURL("", ""); !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing database configuration accepted", err)
	}
}
