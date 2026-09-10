package desktop

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/nats/enrollment/servicecredentials"
)

type ReleaseAdminConfig struct {
	Action          string
	DatabaseURL     string
	DatabaseURLFile string
	Directory       string
	TrustedKeysFile string
	ManifestFile    string
	Digest          string
	Actor           string
}

func LoadReleaseKeys(path string) ([]ed25519.PublicKey, error) {
	data, err := keyfile.Read(path, 8192)
	if err != nil {
		return nil, errors.New("trusted release key file is unavailable or not protected")
	}
	defer clear(data)
	keys := []ed25519.PublicKey{}
	seen := make(map[string]bool)
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN PUBLIC KEY-----")) {
			return nil, artifacts.ErrInvalid
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 {
			return nil, artifacts.ErrInvalid
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, artifacts.ErrInvalid
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, artifacts.ErrInvalid
		}
		id := artifacts.KeyID(key)
		if id == "" || seen[id] || len(keys) >= 8 {
			return nil, artifacts.ErrInvalid
		}
		seen[id] = true
		keys = append(keys, append(ed25519.PublicKey(nil), key...))
		data = rest
	}
	if len(keys) == 0 {
		return nil, artifacts.ErrInvalid
	}
	return keys, nil
}

// RunReleaseAdmin is the server-side release admission command. Database access
// is configured privately; output contains only public release metadata. It
// requires console migrations and never creates schema or loads organization CA
// keys. The command cannot assert native OS signing/notarization on its own.
func RunReleaseAdmin(ctx context.Context, config ReleaseAdminConfig, output io.Writer) error {
	if output == nil {
		return errors.New("release administration requires an output writer")
	}
	if config.Action != "inspect" && config.Action != "accept" && config.Action != "show" && config.Action != "withdraw" {
		return errors.New("choose inspect, accept, show or withdraw")
	}
	if (config.Action == "accept" || config.Action == "withdraw") && !releaseActor(config.Actor) {
		return errors.New("provide a valid administrator or release-pipeline actor")
	}
	if (config.Action == "accept" || config.Action == "inspect") && config.ManifestFile == "" {
		return errors.New("provide an installer manifest file")
	}
	if config.Action == "withdraw" && !releaseDigest(config.Digest) {
		return errors.New("provide the exact current release digest")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if config.Action == "inspect" {
		keys, err := LoadReleaseKeys(config.TrustedKeysFile)
		if err != nil {
			return errors.New("trusted release public keys are unavailable or invalid")
		}
		data, err := readReleaseEnvelope(config.ManifestFile)
		if err != nil {
			return err
		}
		verified, err := artifacts.Verify(data, keys, time.Now(), artifacts.Checkpoint{})
		if err != nil {
			return releaseAdminError(err)
		}
		return writeReleaseMetadata(output, "candidate", verified)
	}
	connection, err := servicecredentials.DatabaseURL(config.DatabaseURL, config.DatabaseURLFile)
	if err != nil || connection == "" {
		return errors.New("configure one protected private agent database connection")
	}
	db, err := sql.Open("pgx", connection)
	if err != nil {
		return errors.New("installer release database is unavailable")
	}
	defer db.Close()
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	if err = db.PingContext(ctx); err != nil {
		return errors.New("installer release database is unavailable")
	}
	var migrated bool
	if err = db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_desktop_migrations WHERE name='migrations/001_releases.sql')`).Scan(&migrated); err != nil || !migrated {
		return errors.New("start the console to apply the desktop release migrations first")
	}
	if config.Action == "withdraw" {
		if err = WithdrawRelease(ctx, db, config.Digest, config.Actor); err != nil {
			return releaseAdminError(err)
		}
		return json.NewEncoder(output).Encode(struct {
			Digest string `json:"digest"`
			Status string `json:"status"`
		}{config.Digest, "withdrawn"})
	}
	keys, err := LoadReleaseKeys(config.TrustedKeysFile)
	if err != nil {
		return errors.New("trusted release public keys are unavailable or invalid")
	}
	catalog, err := NewCatalog(db, config.Directory, keys)
	if err != nil {
		return releaseAdminError(err)
	}
	defer catalog.Close()
	var verified *artifacts.Verified
	if config.Action == "accept" {
		data, err := readReleaseEnvelope(config.ManifestFile)
		if err != nil {
			return err
		}
		verified, err = catalog.Accept(ctx, data, config.Actor)
		if err != nil {
			return releaseAdminError(err)
		}
	} else {
		verified, err = catalog.Current(ctx)
		if err != nil {
			return releaseAdminError(err)
		}
	}
	return writeReleaseMetadata(output, "accepted", verified)
}

func writeReleaseMetadata(output io.Writer, status string, verified *artifacts.Verified) error {
	return json.NewEncoder(output).Encode(struct {
		Status       string               `json:"status"`
		Checkpoint   artifacts.Checkpoint `json:"checkpoint"`
		SigningKeyID string               `json:"signing_key_id"`
		Manifest     artifacts.Manifest   `json:"manifest"`
	}{status, verified.Checkpoint(), verified.SigningKeyID(), verified.Manifest()})
}

func readReleaseEnvelope(path string) ([]byte, error) {
	invalid := errors.New("installer release manifest file is unavailable or invalid")
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > artifacts.MaxEnvelopeSize {
		return nil, invalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, invalid
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, invalid
	}
	data, err := io.ReadAll(io.LimitReader(file, artifacts.MaxEnvelopeSize+1))
	if err != nil || len(data) > artifacts.MaxEnvelopeSize {
		return nil, invalid
	}
	return data, nil
}

func releaseAdminError(err error) error {
	for _, known := range []error{artifacts.ErrInvalid, artifacts.ErrUntrusted, artifacts.ErrExpired, artifacts.ErrRollback, artifacts.ErrTarget, artifacts.ErrPackage, ErrNoRelease, ErrWithdrawn, ErrReleaseFiles, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			return known
		}
	}
	return errors.New("installer release action failed; check database availability and migrations")
}
