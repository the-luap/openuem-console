package desktop

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"time"

	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/bootstrap"
	"github.com/open-uem/nats/enrollment/keyfile"
)

var ErrBootstrapConfiguration = errors.New("desktop bootstrap signing configuration is invalid")

// LoadBootstrapKey reads a dedicated protected PKCS#8 Ed25519 key. It never
// interprets an organization CA or release private key as configuration trust.
// The handler additionally rejects any configured release-key fingerprint.
func LoadBootstrapKey(path string) (ed25519.PrivateKey, error) {
	data, err := keyfile.Read(path, 8<<10)
	if err != nil {
		return nil, ErrBootstrapConfiguration
	}
	defer clear(data)
	if !bytes.HasPrefix(data, []byte("-----BEGIN PRIVATE KEY-----")) {
		return nil, ErrBootstrapConfiguration
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrBootstrapConfiguration
	}
	defer clear(block.Bytes)
	var value asn1.RawValue
	if rest, err := asn1.Unmarshal(block.Bytes, &value); err != nil || len(rest) != 0 {
		return nil, ErrBootstrapConfiguration
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrBootstrapConfiguration
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrBootstrapConfiguration
	}
	defer clear(key)
	if !validBootstrapKey(key) {
		return nil, ErrBootstrapConfiguration
	}
	return bytes.Clone(key), nil
}

func validBootstrapKey(key ed25519.PrivateKey) bool {
	if len(key) != ed25519.PrivateKeySize {
		return false
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	return subtle.ConstantTimeCompare(derived, key) == 1
}

type bootstrapKeyDocument struct {
	Schema int                  `json:"schema"`
	Origin string               `json:"origin"`
	Keys   []bootstrapPublicKey `json:"keys"`
}

type bootstrapPublicKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

func (h *PublicHandler) bootstrapKeys(w http.ResponseWriter, r *http.Request) {
	if len(h.bootstrapKey) == 0 {
		http.NotFound(w, r)
		return
	}
	public := h.bootstrapKey.Public().(ed25519.PublicKey)
	publicJSON(w, r, bootstrapKeyDocument{Schema: bootstrap.Schema, Origin: h.origin, Keys: []bootstrapPublicKey{{KeyID: artifacts.KeyID(public), PublicKey: base64.RawStdEncoding.EncodeToString(public)}}})
}

func (h *PublicHandler) configuration(w http.ResponseWriter, r *http.Request, token string) {
	if len(h.bootstrapKey) == 0 {
		http.NotFound(w, r)
		return
	}
	metadata, err := h.store.InstallerMetadata(r.Context(), h.catalog, token, h.origin)
	if err != nil {
		publicFailure(w, err)
		return
	}
	now := time.Now().UTC()
	data, err := bootstrap.Sign(bootstrap.Config{
		Schema: bootstrap.Schema, Origin: h.origin, Organization: metadata.Organization,
		Site: metadata.Site, TenantID: metadata.TenantID, SiteID: metadata.SiteID,
		Invitation: token, Platform: metadata.Platform, Architecture: metadata.Architecture,
		IssuedAt: now, ExpiresAt: metadata.ExpiresAt, ReleaseDigest: metadata.ReleaseDigest,
		ReleaseEnvelope: metadata.ReleaseEnvelope,
	}, h.bootstrapKey, now)
	if err != nil {
		publicFailure(w, ErrBootstrapConfiguration)
		return
	}
	defer clear(data)
	w.Header().Set("Content-Disposition", `attachment; filename="openuem-enrollment.json"`)
	publicJSON(w, r, json.RawMessage(data))
}
