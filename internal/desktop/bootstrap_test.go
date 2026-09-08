package desktop

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/bootstrap"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

func TestPublicSignedConfigurationIsReadOnlyScopedAndBoundToTheApprovedRelease(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	f := newPublicFixture(t, private)
	clear(private) // the handler must own its signing-key bytes
	for _, method := range []string{"GET", "HEAD"} {
		response, data := publicRequest(t, f.server.Client(), f.server.URL, method, "/enroll/desktop/bootstrap-keys", nil, nil)
		if response.StatusCode != 200 || response.ContentLength <= 0 {
			t.Fatal("public bootstrap key unavailable", response.StatusCode)
		}
		if method == "HEAD" {
			if len(data) != 0 {
				t.Fatal("key HEAD returned a body")
			}
			continue
		}
		var document bootstrapKeyDocument
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		if document.Schema != 1 || document.Origin != "https://uem.example.test" || len(document.Keys) != 1 || document.Keys[0].KeyID != artifacts.KeyID(public) || document.Keys[0].PublicKey != base64.RawStdEncoding.EncodeToString(public) {
			t.Fatal("public key document changed origin or signing identity")
		}
	}
	trust := bootstrap.Trust{Origin: "https://uem.example.test", BootstrapKeys: []ed25519.PublicKey{public}, ReleaseKeys: []ed25519.PublicKey{f.public}, Platform: "windows", Architecture: "amd64"}
	for _, method := range []string{"GET", "HEAD", "GET"} {
		response, data := publicRequest(t, f.server.Client(), f.server.URL, method, f.path("configuration"), nil, nil)
		if response.StatusCode != 200 || response.ContentLength <= 0 || response.Header.Get("Content-Disposition") != `attachment; filename="openuem-enrollment.json"` {
			t.Fatal("configuration download headers incorrect", response.StatusCode)
		}
		if method == "HEAD" {
			if len(data) != 0 {
				t.Fatal("configuration HEAD returned a body")
			}
			continue
		}
		verified, err := bootstrap.Verify(data, trust, time.Now())
		if err != nil {
			t.Fatal("signed server configuration did not verify", err)
		}
		config := verified.Config()
		if config.Invitation != f.request.Invitation || config.Organization != "Test organization" || config.Site != "Isolated site" || config.TenantID != 1 || config.SiteID != 1 || config.ReleaseDigest != f.invitation.ReleaseDigest || config.ExpiresAt.After(f.invitation.ExpiresAt) || verified.Artifact() != f.invitation.Artifact {
			t.Fatal("signed configuration lost invitation/scope/release binding")
		}
		if err := verified.VerifyPackage(bytes.NewReader(f.content)); err != nil {
			t.Fatal(err)
		}
	}
	var uses, identities int
	if err := f.store.db.QueryRow(`SELECT (SELECT uses FROM uem_agent_invitations WHERE id=$1),(SELECT count(*) FROM uem_agent_identities)`, f.invitation.ID).Scan(&uses, &identities); err != nil || uses != 0 || identities != 0 {
		t.Fatal("configuration scanner consumed an invitation", err)
	}
	body, err := json.Marshal(f.request)
	if err != nil {
		t.Fatal(err)
	}
	response, _ := publicRequest(t, f.server.Client(), f.server.URL, "POST", f.path("claim"), body, map[string]string{"Content-Type": "application/json"})
	if response.StatusCode != 200 {
		t.Fatal("fixture claim failed", response.StatusCode)
	}
	response, data := publicRequest(t, f.server.Client(), f.server.URL, "GET", f.path("configuration"), nil, nil)
	if response.StatusCode != 200 {
		t.Fatal("consumed invitation lost safe same-key recovery configuration", response.StatusCode)
	}
	if _, err := bootstrap.Verify(data, trust, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := f.catalog.Withdraw(context.Background(), f.invitation.ReleaseDigest, "fixture-admin"); err != nil {
		t.Fatal(err)
	}
	response, data = publicRequest(t, f.server.Client(), f.server.URL, "GET", f.path("configuration"), nil, nil)
	if response.StatusCode != 404 || strings.Contains(string(data), f.request.Invitation) {
		t.Fatal("withdrawn release remained available or reflected its invitation", response.StatusCode)
	}
	f.handler.Close()
	if !bytes.Equal(f.handler.bootstrapKey, make([]byte, ed25519.PrivateKeySize)) {
		t.Fatal("closed handler retained its owned signing-key bytes")
	}
}

func TestBootstrapConfigurationRequiresItsDedicatedKeyAndAnActiveInvitation(t *testing.T) {
	f := newPublicFixture(t)
	for _, path := range []string{f.path("configuration"), "/enroll/desktop/bootstrap-keys"} {
		response, _ := publicRequest(t, f.server.Client(), f.server.URL, "GET", path, nil, nil)
		if response.StatusCode != 404 {
			t.Fatal("unconfigured bootstrap signer exposed a document", response.StatusCode)
		}
	}
	if handler, err := NewPublicHandler(f.store, f.catalog, "https://uem.example.test", clientidentity.Policy{}, f.private); !errors.Is(err, ErrBootstrapConfiguration) {
		if handler != nil {
			handler.Close()
		}
		t.Fatal("release key was accepted as a configuration signer", err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	signed := newPublicFixture(t, key)
	if _, err := signed.store.db.Exec(`UPDATE uem_agent_invitations SET revoked_at=clock_timestamp() WHERE id=$1`, signed.invitation.ID); err != nil {
		t.Fatal(err)
	}
	response, _ := publicRequest(t, signed.server.Client(), signed.server.URL, "GET", signed.path("configuration"), nil, nil)
	if response.StatusCode != 404 {
		t.Fatal("revoked invitation received a signed configuration", response.StatusCode)
	}
}

func TestBootstrapSigningKeyLoaderRequiresOneProtectedEd25519Key(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(encoded)
	path := filepath.Join(t.TempDir(), "bootstrap-key.pem")
	if err := keyfile.Create(path, encoded); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadBootstrapKey(path)
	if err != nil || !bytes.Equal(loaded, private) {
		t.Fatal("protected configuration key was rejected", err)
	}
	clear(loaded)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadBootstrapKey(path); !errors.Is(err, ErrBootstrapConfiguration) {
			t.Fatal("shared private-key file accepted", err)
		}
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKCS8PrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(otherDER)
	for _, data := range [][]byte{
		[]byte("not a signing key"),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: append(bytes.Clone(der), 0)}),
		append(bytes.Clone(encoded), encoded...),
		append([]byte("ignored prefix\n"), encoded...),
	} {
		path := filepath.Join(t.TempDir(), "invalid-bootstrap-key.pem")
		if err := keyfile.Create(path, data); err != nil {
			t.Fatal(err)
		}
		clear(data)
		if _, err := LoadBootstrapKey(path); !errors.Is(err, ErrBootstrapConfiguration) {
			t.Fatal("wrong or ambiguous signing key accepted", err)
		}
	}
}
