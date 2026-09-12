package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func databaseConfig() DatabaseConfig {
	return DatabaseConfig{Version: 1, Installation: strings.Repeat("1", 32), Host: "database.internal", Port: 5432, Database: "openuem", User: "console", TrustFile: "/run/openuem/database-ca.pem"}
}

func TestInstallationSecretsDatabaseConfig(t *testing.T) {
	valid := databaseConfig()
	data, _ := json.Marshal(valid)
	if result, err := DecodeDatabaseConfig(data); err != nil || result != valid {
		t.Fatal("valid metadata rejected", err)
	}
	if result, err := LoadDatabaseConfig(privateFile(t, string(data))); err != nil || result != valid {
		t.Fatal("protected metadata rejected", err)
	}
	for _, extra := range []string{`{"unknown":"synthetic-secret",`, `{"host":"unreviewed",`, `{"\u0068ost":"unreviewed",`, `{"Host":"unreviewed",`, `{"HOST":"unreviewed",`} {
		if _, err := DecodeDatabaseConfig(append([]byte(extra), data[1:]...)); !errors.Is(err, ErrConfiguration) {
			t.Fatal("unknown or repeated configuration accepted", err)
		}
	}
	for _, input := range [][]byte{nil, []byte(`[]`), append(append([]byte{}, data...), []byte(`{}`)...), bytes.Repeat([]byte("x"), 8193)} {
		if _, err := DecodeDatabaseConfig(input); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid configuration accepted", err)
		}
	}
	for _, change := range []func(*DatabaseConfig){func(c *DatabaseConfig) { c.Version = 2 }, func(c *DatabaseConfig) { c.Installation = "" }, func(c *DatabaseConfig) { c.Port = 0 }, func(c *DatabaseConfig) { c.Host = "db/path" }, func(c *DatabaseConfig) { c.Host = "0.0.0.0" }, func(c *DatabaseConfig) { c.Host = "::" }, func(c *DatabaseConfig) { c.Host = "ff02::1" }, func(c *DatabaseConfig) { c.User = "postgres" }, func(c *DatabaseConfig) { c.User = "pg_internal" }, func(c *DatabaseConfig) { c.Database = "template1" }, func(c *DatabaseConfig) { c.Database = "postgres" }, func(c *DatabaseConfig) { c.TrustFile = "../root.pem" }, func(c *DatabaseConfig) { c.TrustFile = "/root.pem\n" }} {
		config := valid
		change(&config)
		if config.Validate() == nil {
			t.Fatal("invalid deployment metadata accepted")
		}
	}
	for _, host := range []string{"database", "database.internal", "127.0.0.1", "::1", "2001:db8::1"} {
		config := valid
		config.Host = host
		if config.Validate() != nil {
			t.Fatal("valid database host rejected")
		}
	}
}
