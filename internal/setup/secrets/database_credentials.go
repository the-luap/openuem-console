package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
)

const (
	DatabasePasswordFile              = "database-password"
	DatabaseAdministratorPasswordFile = "administrator-password"
	DatabaseURLFile                   = "database.url"
)

var databaseArtifacts = []string{DatabasePasswordFile, DatabaseAdministratorPasswordFile, DatabaseURLFile}
var databaseIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
var databaseHost = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)

// DatabaseConfig contains public deployment metadata only. The application role
// differs from the bootstrap superuser, whose fixed PostgreSQL role is postgres.
// TrustFile is the absolute CA mount path as seen by the application container.
type DatabaseConfig struct {
	Version      int    `json:"version"`
	Installation string `json:"installation"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Database     string `json:"database"`
	User         string `json:"user"`
	TrustFile    string `json:"trust_file"`
}

func (config DatabaseConfig) Validate() error {
	if config.Version != 1 || !validInstallation(config.Installation) || config.Port < 1 || config.Port > 65535 || len(config.Host) > 253 ||
		!databaseIdentifier.MatchString(config.Database) || !databaseIdentifier.MatchString(config.User) ||
		strings.HasPrefix(config.Database, "pg_") || strings.HasPrefix(config.User, "pg_") || config.User == "postgres" ||
		config.Database == "postgres" || config.Database == "template0" || config.Database == "template1" ||
		!path.IsAbs(config.TrustFile) || path.Clean(config.TrustFile) != config.TrustFile || config.TrustFile == "/" || len(config.TrustFile) > 1024 ||
		strings.ContainsFunc(config.TrustFile, func(r rune) bool { return r < 33 || r > 126 }) {
		return ErrConfiguration
	}
	if addr, err := netip.ParseAddr(config.Host); err == nil {
		if addr.Zone() != "" || addr.String() != config.Host || addr.IsUnspecified() || addr.IsMulticast() {
			return ErrConfiguration
		}
	} else if !databaseHost.MatchString(config.Host) {
		return ErrConfiguration
	}
	return nil
}

// DecodeDatabaseConfig rejects unknown fields and extra JSON documents, without
// repeating input text in errors. The input is bounded even before decoding.
func DecodeDatabaseConfig(data []byte) (DatabaseConfig, error) {
	var config DatabaseConfig
	if len(data) == 0 || len(data) > 8192 || !uniqueDatabaseConfig(data) {
		return config, ErrConfiguration
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || config.Validate() != nil {
		return DatabaseConfig{}, ErrConfiguration
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return DatabaseConfig{}, ErrConfiguration
	}
	return config, nil
}

func LoadDatabaseConfig(path string) (DatabaseConfig, error) {
	data, err := read(path, 8192)
	if err != nil {
		return DatabaseConfig{}, ErrConfiguration
	}
	defer clear(data)
	return DecodeDatabaseConfig(data)
}

func uniqueDatabaseConfig(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return false
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return false
		}
		// encoding/json accepts case-folded struct field names. Only the exact
		// public schema spelling is allowed, preventing semantic duplicates.
		switch name {
		case "version", "installation", "host", "port", "database", "user", "trust_file":
		default:
			return false
		}
		seen[name] = true
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return false
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}

type databaseJournal struct {
	Config                DatabaseConfig `json:"config"`
	Password              string         `json:"password"`
	AdministratorPassword string         `json:"administrator_password"`
}

// InitializeDatabaseCredentials creates separate bootstrap/application passwords
// and a verify-full connection URL. It never contacts PostgreSQL or changes a
// database account. The bound metadata and every completed byte survive retries.
func InitializeDatabaseCredentials(ctx context.Context, directory string, config DatabaseConfig) (Result, error) {
	return initializeDatabaseCredentials(ctx, directory, config, nil)
}

func initializeDatabaseCredentials(ctx context.Context, directory string, config DatabaseConfig, afterWrite func(string) error) (Result, error) {
	if config.Validate() != nil {
		return Result{}, ErrConfiguration
	}
	d, err := openProvisioning(ctx, directory, append([]string{"credentials.json", "manifest.json"}, databaseArtifacts...), afterWrite)
	if err != nil {
		return Result{}, err
	}
	if !d.present["credentials.json"] {
		if len(d.present) != 0 {
			return Result{}, ErrState
		}
		var raw [64]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return Result{}, ErrState
		}
		state := databaseJournal{Config: config, Password: base64.RawURLEncoding.EncodeToString(raw[:32]), AdministratorPassword: base64.RawURLEncoding.EncodeToString(raw[32:])}
		clear(raw[:])
		encoded, err := json.Marshal(state)
		if err != nil {
			return Result{}, ErrState
		}
		defer clear(encoded)
		if err := d.write("credentials.json", encoded); err != nil {
			return Result{}, err
		}
	}
	encoded, err := d.read("credentials.json", 4096)
	if err != nil {
		return Result{}, err
	}
	defer clear(encoded)
	var state databaseJournal
	if json.Unmarshal(encoded, &state) != nil || state.Config != config || !validDatabasePassword(state.Password) || !validDatabasePassword(state.AdministratorPassword) || state.Password == state.AdministratorPassword {
		return Result{}, ErrState
	}
	canonical, err := json.Marshal(state)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Result{}, ErrState
	}
	connection := url.URL{Scheme: "postgres", Host: net.JoinHostPort(config.Host, strconv.Itoa(config.Port)), Path: "/" + config.Database, User: url.UserPassword(config.User, state.Password)}
	query := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {config.TrustFile}}
	connection.RawQuery = query.Encode()
	values := []string{state.Password, state.AdministratorPassword, connection.String()}
	marker := manifest{Version: 1, Installation: config.Installation, Files: map[string]string{}}
	for index, name := range databaseArtifacts {
		value := []byte(values[index])
		if !d.present[name] {
			if d.present["manifest.json"] {
				clear(value)
				return Result{}, ErrState
			}
			if err := d.write(name, value); err != nil {
				clear(value)
				return Result{}, err
			}
		}
		actual, err := d.read(name, 8192)
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
	if d.present["manifest.json"] {
		actual, err := d.read("manifest.json", 2048)
		if err != nil || !bytes.Equal(data, actual) {
			return Result{}, ErrState
		}
	} else if err := d.write("manifest.json", data); err != nil {
		return Result{}, err
	}
	if err := d.check(); err != nil {
		return Result{}, err
	}
	return Result{Installation: config.Installation}, nil
}

func validDatabasePassword(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	defer clear(decoded)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}
