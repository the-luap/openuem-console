package desktop

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/keyfile"
)

func TestReleaseAdministrationCommandUsesPersistedCatalogAndRedactedOutput(t *testing.T) {
	f := newCatalogFixture(t)
	data, expected, _ := f.prepare(t, f.manifest)
	manifestPath := filepath.Join(f.directory, "release.json")
	if err := os.WriteFile(manifestPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(f.public)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "release-public-keys.pem")
	if err = keyfile.Create(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err = f.store.db.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	databaseURL, err := url.Parse(os.Getenv("AGENT_ENROLLMENT_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	query := databaseURL.Query()
	query.Set("search_path", schema)
	databaseURL.RawQuery = query.Encode()
	config := ReleaseAdminConfig{Action: "accept", DatabaseURL: databaseURL.String(), Directory: f.directory, TrustedKeysFile: keyPath, ManifestFile: manifestPath, Actor: "release-cli-test"}
	var output bytes.Buffer
	inspect := config
	inspect.Action = "inspect"
	inspect.DatabaseURL = ""
	inspect.Directory = ""
	inspect.Actor = ""
	if err = RunReleaseAdmin(context.Background(), inspect, &output); err != nil || !strings.Contains(output.String(), `"status":"candidate"`) {
		t.Fatal("could not inspect a candidate without database or package access", err)
	}
	if _, err = f.catalog.Current(context.Background()); !errors.Is(err, ErrNoRelease) {
		t.Fatal("inspection approved a release", err)
	}
	output.Reset()
	if err = RunReleaseAdmin(context.Background(), config, &output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Checkpoint artifacts.Checkpoint `json:"checkpoint"`
		Manifest   artifacts.Manifest   `json:"manifest"`
	}
	if err = json.Unmarshal(output.Bytes(), &result); err != nil || result.Checkpoint != expected.Checkpoint() || result.Manifest.Version != f.manifest.Version {
		t.Fatal("command returned incorrect release metadata", err)
	}
	for _, secret := range []string{databaseURL.String(), "PRIVATE KEY", "local-test-only"} {
		if strings.Contains(output.String(), secret) {
			t.Fatal("command output disclosed a secret")
		}
	}
	output.Reset()
	config.Action = "show"
	if err = RunReleaseAdmin(context.Background(), config, &output); err != nil {
		t.Fatal("could not read accepted state through another database connection", err)
	}
	// Emergency withdrawal must work independently of files and trust-key access.
	output.Reset()
	config.Action = "withdraw"
	config.Digest = expected.Digest()
	config.Directory = ""
	config.TrustedKeysFile = ""
	if err = RunReleaseAdmin(context.Background(), config, &output); err != nil {
		t.Fatal("withdrawal incorrectly requires the package filesystem", err)
	}
	if !strings.Contains(output.String(), `"status":"withdrawn"`) {
		t.Fatal("withdrawal result is missing")
	}
	if _, err = f.catalog.Current(context.Background()); !errors.Is(err, ErrWithdrawn) {
		t.Fatal("command withdrawal did not affect the live catalog", err)
	}
}

func TestReleaseKeyLoaderRejectsPrivateOtherDuplicateAndMalformedKeys(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateDER)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"private":         pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		"other algorithm": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}),
		"duplicate":       append(append([]byte(nil), publicPEM...), publicPEM...),
		"trailing data":   append(append([]byte(nil), publicPEM...), []byte("unexpected data")...),
		"leading data":    append([]byte("unexpected data"), publicPEM...),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "keys.pem")
			if err := keyfile.Create(path, data); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadReleaseKeys(path); err == nil {
				t.Fatal("accepted an invalid release trust file")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "keys.pem")
	if err = keyfile.Create(path, publicPEM); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadReleaseKeys(path)
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0], public) {
		t.Fatal("valid public key was rejected or corrupted by buffer cleanup", err)
	}
}

func TestReleaseCommandDoesNotExposeDatabaseParseErrors(t *testing.T) {
	var output bytes.Buffer
	err := RunReleaseAdmin(context.Background(), ReleaseAdminConfig{Action: "show", DatabaseURL: "postgres://secret-marker@[%invalid"}, &output)
	if err == nil || strings.Contains(err.Error(), "secret-marker") || output.Len() != 0 {
		t.Fatal("database parse failure was not redacted")
	}
}
