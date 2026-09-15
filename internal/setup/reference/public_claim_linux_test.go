//go:build linux

package reference

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/bootstrap"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/nats/enrollment/servicecredentials"
	"github.com/open-uem/openuem-console/internal/desktop"
	"github.com/open-uem/openuem-console/internal/desktop/protocol"
)

const referenceOrigin = "https://uem.example.test:8443"

type invitationRecord struct {
	Token, ReleaseDigest string
	registry.Scope
}

// This trusted fixture prepares an invitation through the production store. It
// does not stand in for console permission/UI acceptance. The public claim probe
// receives no database, server encryption key, CA private key or service seed.
func TestReferenceInvitation(t *testing.T) {
	fixture(t)
	dsn, err := servicecredentials.DatabaseURL("", "/run/database.url")
	if err != nil {
		t.Fatal("reference database credential is unavailable")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("reference database could not open")
	}
	defer db.Close()
	master, err := servicecredentials.EncryptionKey("", "/run/encryption.key")
	if err != nil {
		t.Fatal("reference registry key is unavailable")
	}
	store, err := desktop.NewStore(db, master)
	if err != nil {
		t.Fatal("reference desktop store is unavailable")
	}
	keys, err := desktop.LoadReleaseKeys("/run/release-keys.pem")
	if err != nil {
		t.Fatal("reference release trust is unavailable")
	}
	catalog, err := desktop.NewCatalog(db, "/releases", keys)
	if err != nil {
		t.Fatal("reference release catalog is unavailable")
	}
	defer catalog.Close()
	ctx := t.Context()
	current, err := catalog.Current(ctx)
	if err != nil {
		t.Fatal("reference release job did not approve a current installer")
	}
	record := invitationRecord{ReleaseDigest: current.Digest()}
	if err = db.QueryRowContext(ctx, `SELECT tenant_sites,id FROM sites ORDER BY id LIMIT 1`).Scan(&record.TenantID, &record.SiteID); err != nil {
		t.Fatal("reference organization and site are unavailable")
	}
	if _, err = store.Registry.EnsureAuthority(ctx, record.TenantID, "Reference", referenceOrigin, "first-admin", nil, nil); err != nil {
		t.Fatal("cannot initialize the reference enrollment authority")
	}
	invitation, err := store.InviteInstaller(ctx, catalog, registry.InvitationOptions{Scope: record.Scope,
		Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(30 * time.Minute)},
		record.ReleaseDigest, referenceOrigin, "first-admin")
	if err != nil {
		t.Fatal("cannot create the release-bound reference invitation")
	}
	record.Token = strings.TrimPrefix(invitation.URL, referenceOrigin+"/enroll/desktop/")
	if !enrollment.ValidToken(record.Token) || invitation.ReleaseDigest != record.ReleaseDigest {
		t.Fatal("reference invitation lost its origin or release binding")
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal("cannot encode reference invitation")
	}
	write(t, "/device/invitation.json", encoded)
}

func referenceMetadata(t *testing.T, record invitationRecord, uses int) {
	t.Helper()
	keys, err := desktop.LoadReleaseKeys("/run/release-keys.pem")
	if err != nil {
		t.Fatal("reference release trust is unavailable")
	}
	client := client(t)
	// HEAD and repeated GET model link scanners; none may reserve a use.
	for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodGet} {
		r, err := http.NewRequestWithContext(t.Context(), method, referenceOrigin+"/enroll/desktop/"+record.Token+"/metadata", nil)
		if err != nil {
			t.Fatal("cannot prepare public metadata request")
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("public invitation metadata transport failed")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 96<<10))
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("public invitation metadata is unavailable or cacheable")
		}
		if method == http.MethodHead {
			if len(body) != 0 {
				t.Fatal("metadata HEAD returned a body")
			}
			continue
		}
		var metadata desktop.InstallerMetadata
		if json.Unmarshal(body, &metadata) != nil || metadata.Version != enrollment.Version || metadata.TenantID != record.TenantID || metadata.SiteID != record.SiteID || metadata.AvailableUses != uses || metadata.ReleaseDigest != record.ReleaseDigest || metadata.Platform != "windows" || metadata.Architecture != "amd64" {
			t.Fatal("public invitation metadata changed its scope, uses or release")
		}
		release, err := artifacts.Verify(metadata.ReleaseEnvelope, keys, time.Now(), artifacts.Checkpoint{})
		if err != nil || release.Digest() != record.ReleaseDigest {
			t.Fatal("public metadata did not preserve the trusted release envelope")
		}
		target, err := release.Select("windows", "amd64")
		if err != nil || metadata.Artifact != target || metadata.DownloadURL != referenceOrigin+protocol.DownloadPath(record.ReleaseDigest, "windows", "amd64") {
			t.Fatal("public metadata changed the authenticated installer target")
		}
	}
}

// The gateway authenticates the origin's bootstrap public keys. Release trust
// comes from the fixture's separate release pipeline, never from that response.
func referenceBootstrapDelivery(t *testing.T, transport *enrollment.HTTPClient, invitation invitationRecord, action string) {
	t.Helper()
	document, err := transport.BootstrapKeys(t.Context())
	if err != nil {
		t.Fatal("public bootstrap key discovery failed")
	}
	keys, err := bootstrap.ParseOriginKeys(document, referenceOrigin)
	if err != nil {
		t.Fatal("public bootstrap keys did not bind the authorized origin")
	}
	if action == "" {
		write(t, "/device/bootstrap-keys.json", document)
	} else {
		retained, err := os.ReadFile("/device/bootstrap-keys.json")
		if err != nil || !bytes.Equal(retained, document) {
			t.Fatal("service restart changed the retained bootstrap signing identity")
		}
	}
	configuration, err := transport.Configuration(t.Context(), invitation.Token)
	if action == "withdrawn" {
		if !errors.Is(err, enrollment.ErrEnrollmentUnavailable) {
			t.Fatal("withdrawn release still supplied a signed configuration")
		}
	} else {
		if err != nil {
			t.Fatal("public signed configuration download failed")
		}
		releaseKeys, err := desktop.LoadReleaseKeys("/run/release-keys.pem")
		if err != nil {
			t.Fatal("independent release trust is unavailable")
		}
		trust := bootstrap.Trust{Origin: referenceOrigin, BootstrapKeys: keys, ReleaseKeys: releaseKeys,
			Platform: "windows", Architecture: "amd64"}
		verified, err := bootstrap.Verify(configuration, trust, time.Now())
		if err != nil {
			t.Fatal("delivered bootstrap and release signatures did not verify independently")
		}
		config := verified.Config()
		if config.Invitation != invitation.Token || config.TenantID != invitation.TenantID || config.SiteID != invitation.SiteID || config.ReleaseDigest != invitation.ReleaseDigest || verified.DownloadURL() != referenceOrigin+protocol.DownloadPath(invitation.ReleaseDigest, "windows", "amd64") {
			t.Fatal("signed configuration changed the invitation scope or approved release")
		}
		if verified.VerifyPackage(strings.NewReader(referencePackage)) != nil || verified.VerifyAgent(strings.NewReader(referenceAgent)) != nil {
			t.Fatal("signed configuration does not bind the synthetic package and agent bytes")
		}
		wrong := trust
		wrong.Architecture = "arm64"
		if _, err = bootstrap.Verify(configuration, wrong, time.Now()); !errors.Is(err, bootstrap.ErrTarget) {
			t.Fatal("signed configuration authorized a different endpoint architecture")
		}
		wrong = trust
		wrong.ReleaseKeys, wrong.BootstrapKeys = trust.BootstrapKeys, trust.ReleaseKeys
		if _, err = bootstrap.Verify(configuration, wrong, time.Now()); err == nil {
			t.Fatal("public bootstrap trust substituted for independent release trust")
		}
	}
	client := client(t)
	base := "/enroll/desktop/" + invitation.Token
	for _, path := range []string{base, base + "/invitation", base + "/configuration"} {
		for _, method := range []string{http.MethodHead, http.MethodGet} {
			r, err := http.NewRequestWithContext(t.Context(), method, referenceOrigin+path, nil)
			if err != nil {
				t.Fatal("cannot prepare public enrollment file request")
			}
			response, err := client.Do(r)
			if err != nil {
				t.Fatal("public enrollment file request failed")
			}
			body, err := io.ReadAll(io.LimitReader(response.Body, 96<<10))
			response.Body.Close()
			status := http.StatusOK
			if action == "withdrawn" {
				status = http.StatusNotFound
			}
			if err != nil || response.StatusCode != status || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || method == http.MethodHead && len(body) != 0 {
				t.Fatal("public enrollment files lost status, privacy or HEAD semantics")
			}
			if action == "withdrawn" || method == http.MethodHead {
				continue
			}
			switch path {
			case base:
				if !bytes.Contains(body, []byte(`href="`+base+`/invitation"`)) || !bytes.Contains(body, []byte(`href="`+base+`/configuration"`)) {
					t.Fatal("compatible enrollment portal omitted its native enrollment files")
				}
			case base + "/invitation":
				if string(body) != invitation.Token+"\n" || response.Header.Get("Content-Disposition") != `attachment; filename="openuem-invitation.txt"` {
					t.Fatal("public invitation download changed its limited token or attachment name")
				}
			case base + "/configuration":
				if response.Header.Get("Content-Disposition") != `attachment; filename="openuem-enrollment.json"` {
					t.Fatal("public signed configuration lost its attachment name")
				}
			}
		}
	}
}

func TestReferencePublicClaim(t *testing.T) {
	fixture(t)
	var invitation invitationRecord
	data, err := os.ReadFile("/device/invitation.json")
	if err != nil || json.Unmarshal(data, &invitation) != nil || !enrollment.ValidToken(invitation.Token) {
		t.Fatal("reference invitation is unavailable")
	}
	transport, err := enrollment.NewHTTPClient(referenceOrigin, roots(t))
	if err != nil {
		t.Fatal("cannot initialize the public enrollment client")
	}
	defer transport.CloseIdleConnections()
	action := os.Getenv("OPENUEM_REFERENCE_ACTION")
	referenceBootstrapDelivery(t, transport, invitation, action)
	if action == "retry" || action == "withdrawn" {
		var claim enrollment.Request
		data, err := os.ReadFile("/device/claim.json")
		if err != nil || json.Unmarshal(data, &claim) != nil {
			t.Fatal("retained endpoint proof is unavailable")
		}
		issued, err := transport.Claim(t.Context(), claim)
		if action == "withdrawn" {
			if !errors.Is(err, enrollment.ErrEnrollmentUnavailable) {
				t.Fatal("withdrawn release still authorized a public claim")
			}
			status, _, _ := request(t, client(t), "/enroll/desktop/"+invitation.Token+"/metadata", nil)
			if status != http.StatusNotFound {
				t.Fatal("withdrawn release invitation metadata remained available")
			}
			return
		}
		encoded, encodeErr := json.Marshal(issued)
		retained, readErr := os.ReadFile("/device/response.json")
		if err != nil || encodeErr != nil || readErr != nil || !bytes.Equal(encoded, retained) {
			t.Fatal("public claim retry after restart changed the issued identity")
		}
		referenceMetadata(t, invitation, 0)
		return
	}
	if action != "" {
		t.Fatal("unknown public claim fixture action")
	}
	referenceMetadata(t, invitation, 1)
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal("cannot create public endpoint keys")
	}
	defer keys.Broker.Wipe()
	claim, err := keys.Request(invitation.Token, "windows", "amd64", "Reference endpoint")
	if err != nil {
		t.Fatal("cannot prepare endpoint key proof")
	}
	// Persist this synthetic endpoint's own pending keys before any issuance, as
	// the production client requires. No host enrollment or service is installed.
	private, err := x509.MarshalPKCS8PrivateKey(keys.Certificate)
	if err != nil {
		t.Fatal("cannot encode the endpoint certificate key")
	}
	defer clear(private)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	defer clear(privatePEM)
	write(t, "/device/certificate.key", privatePEM)
	seed, err := keys.Broker.Seed()
	if err != nil {
		t.Fatal("cannot encode the endpoint broker key")
	}
	defer clear(seed)
	write(t, "/device/broker.seed", seed)
	encoded, _ := json.Marshal(claim)
	write(t, "/device/claim.json", encoded)
	invalid := *claim
	invalid.Proof = "invalid"
	body, _ := json.Marshal(invalid)
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, referenceOrigin+"/enroll/desktop/"+invitation.Token+"/claim", bytes.NewReader(body))
	if err != nil {
		t.Fatal("cannot prepare invalid public proof")
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := client(t).Do(r)
	if err != nil {
		t.Fatal("invalid public proof transport failed")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatal("public claim accepted an invalid broker proof")
	}
	referenceMetadata(t, invitation, 1)
	issued, err := transport.Claim(t.Context(), *claim)
	if err != nil || issued.TenantID != invitation.TenantID || issued.SiteID != invitation.SiteID {
		t.Fatal("public gateway claim failed or changed the invitation scope")
	}
	// HTTPClient already validates the certificate, CSR key and exact WSS origin.
	encoded, _ = json.Marshal(issued)
	write(t, "/device/response.json", encoded)
	retry, err := transport.Claim(t.Context(), *claim)
	retried, _ := json.Marshal(retry)
	if err != nil || !bytes.Equal(encoded, retried) {
		t.Fatal("same-key public claim did not recover the same identity")
	}
	other, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal("cannot create competing endpoint keys")
	}
	defer other.Broker.Wipe()
	competing, err := other.Request(invitation.Token, "windows", "amd64", "Competing endpoint")
	if err != nil {
		t.Fatal("cannot prepare competing endpoint proof")
	}
	if _, err = transport.Claim(t.Context(), *competing); !errors.Is(err, enrollment.ErrEnrollmentUnavailable) {
		t.Fatal("one-use invitation authorized different endpoint keys")
	}
	referenceMetadata(t, invitation, 0)
	encoded, _ = json.Marshal(deviceRecord{ID: issued.DeviceID, Scope: invitation.Scope})
	write(t, "/device/record.json", encoded)
}
