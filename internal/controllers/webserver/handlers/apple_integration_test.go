package handlers

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"mime/multipart"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/open-uem/openuem-console/internal/security/sessiongeneration"
	"github.com/open-uem/openuem-console/internal/views/locales"
)

func TestNativeAppleConsoleRoutesWithPostgres(t *testing.T) {
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for console integration")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "apple_console_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	t.Setenv("ENV", "test")
	m, err := models.New(u.String(), "pgx", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.Close()
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	if _, err = m.Client.Settings.Create().Save(ctx); err != nil {
		t.Fatal(err)
	}
	if err = sessiongeneration.Migrate(ctx, m.DB); err != nil {
		t.Fatal(err)
	}
	settings, err := m.GetAuthenticationSettings()
	if err != nil {
		t.Fatal(err)
	}
	if err = settings.Update().SetUseCertificates(true).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err = m.CreateDefaultTenantAndSite(); err != nil {
		t.Fatal(err)
	}
	tenant, err := m.GetDefaultTenant()
	if err != nil {
		t.Fatal(err)
	}
	site, err := m.GetDefaultSite(tenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Client.User.Create().SetID("apple-console-admin").SetName("Console Admin").SetEmail("admin@example.test").SetUse2fa(false).SetRegister(nats.REGISTER_COMPLETE).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Client.Agent.Create().SetID("windows-fixture").SetHostname("Finance-PC").SetNickname("Finance Windows").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(site.ID).SetLastContact(time.Now()).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if err = m.Client.OperatingSystem.Create().SetType("windows").SetUsername("finance").SetVersion("Windows 11").SetDescription("Windows 11 Enterprise").SetOwnerID("windows-fixture").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err = m.Client.Computer.Create().SetManufacturer("Example").SetModel("Laptop").SetMemory(16000000000).SetProcessor("Intel").SetProcessorArch("amd64").SetProcessorCores(8).SetOwnerID("windows-fixture").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	store, err := apple.NewStore(m.DB, strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = locales.Load(); err != nil {
		t.Fatal(err)
	}
	ctx, err = locales.WithLocale(ctx, "en")
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	sm.Put(ctx, "uid", "apple-console-admin")
	sm.Put(ctx, "usepasswd", false)
	releases := t.TempDir()
	if err = os.WriteFile(filepath.Join(releases, "latest.json"), []byte(`{"Version":"0.11.0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	permissions, err := access.NewStore(m.DB)
	if err != nil {
		t.Fatal(err)
	}
	if err = permissions.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = permissions.Bootstrap(ctx, "apple-console-admin"); err != nil {
		t.Fatal(err)
	}
	audits, err := audit.NewStore(m.DB, permissions)
	if err != nil {
		t.Fatal(err)
	}
	if err = audits.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	h := &Handler{Access: permissions, Model: m, Apple: store, SessionManager: &sessions.SessionManager{Manager: sm}, Version: "0.11.0", ServerReleasesFolder: releases}
	stampOwnedConsoleSession(t, h, ctx, "apple-console-admin")
	e := echo.New()
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error { c.Set("csrf", "console-test-token"); return next(c) }
	})
	h.Register(e, 3)
	t.Run("OIDC account identity administration", func(t *testing.T) { exerciseOIDCAccountRoutes(t, h, e, ctx, tenant.ID, site.ID) })
	base := "/tenant/" + strconv.Itoa(tenant.ID)
	request := func(method, path, contentType string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader(body)).WithContext(ctx)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	rec := request("GET", base+"/ios/setup", "", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Apple push certificate") {
		t.Fatal("setup page failed", rec.Code, rec.Body.String())
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "Test APNs", ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: "com.apple.mgmt.console-test"}}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 3, 2}, Value: []byte{5, 0}}}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for name, value := range map[string]string{"csrf": "console-test-token", "organization": "Example organization", "public_url": "https://mdm.example.test"} {
		if err = writer.WriteField(name, value); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string][]byte{"push_certificate": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "push_key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})} {
		part, err := writer.CreateFormFile(name, name+".pem")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = part.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	rec = request("POST", base+"/ios/setup", writer.FormDataContentType(), body.Bytes())
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), apple.ErrPushCertificate.Error()) || strings.Contains(rec.Body.String(), "credentials saved") {
		t.Fatal("setup accepted an untrusted certificate", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "BEGIN PRIVATE KEY") {
		t.Fatal("private key leaked in setup response")
	}
	if _, err = store.SettingsMetadata(ctx, tenant.ID); !errors.Is(err, apple.ErrNotFound) {
		t.Fatal("rejected upload configured management", err)
	}
	// Seed an existing installation in this disposable schema to exercise the
	// remaining routes. This does not add synthetic trust to the production store
	// or claim a successful Apple certificate upload. The secret encoding is built
	// independently from the documented AES-GCM storage format.
	ca := &x509.Certificate{SerialNumber: big.NewInt(124), Subject: pkix.Name{CommonName: "Synthetic console enrollment CA"}, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	seedExistingAppleSettings(t, m.DB, apple.Settings{TenantID: tenant.ID, PublicURL: "https://mdm.example.test", Organization: "Example organization", Topic: "com.apple.mgmt.console-test", PushExpiresAt: cert.NotAfter, PushCertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), PushKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), CACertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), CAKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})})
	form := url.Values{"csrf": {"console-test-token"}, "name": {"Sales iPhone"}, "site_id": {strconv.Itoa(site.ID)}}
	rec = request("POST", base+"/ios/enroll", "application/x-www-form-urlencoded", []byte(form.Encode()))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Enrollment invitation ready") {
		t.Fatal("enrollment form failed", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("enrollment secret page is cacheable")
	}
	rec = request("GET", base+"/devices", "", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Finance Windows") || !strings.Contains(rec.Body.String(), "Sales iPhone") {
		t.Fatal("unified device query failed", rec.Code, rec.Body.String())
	}
	// An invitation's name is not platform evidence. Native filters use the
	// reported model and never include unrelated desktop rows.
	for _, model := range []struct{ value, platform string }{{"iPhone16,1", "ios"}, {"iPad16,6", "ipados"}, {"Mac16,1", "macos"}, {"AppleTV14,1", "unknown"}, {"", "unknown"}} {
		if _, err = m.DB.Exec(`UPDATE mdm_apple_devices SET model=$1 WHERE tenant_id=$2`, model.value, tenant.ID); err != nil {
			t.Fatal(err)
		}
		for _, filter := range []string{"ios", "ipados", "macos", "linux", "windows", "unknown", "apple"} {
			rec = request("GET", base+"/devices?platform="+filter, "", nil)
			if rec.Code != 200 {
				t.Fatal("platform route failed", filter, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "Sales iPhone") != (filter == model.platform || filter == "apple") || strings.Contains(rec.Body.String(), "Finance Windows") != (filter == "windows") {
				t.Fatal("incorrect platform filter", model, filter)
			}
		}
	}
	rec = request("GET", base+"/devices?platform=android", "", nil)
	if rec.Code != 400 {
		t.Fatal("invalid filter widened device scope", rec.Code)
	}
	form = url.Values{"csrf": {"console-test-token"}, "editor": {"passcode"}, "name": {"Company PIN"}, "identifier": {"eu.example.pin"}, "min_length": {"6"}}
	rec = request("POST", base+"/ios/configurations", "application/x-www-form-urlencoded", []byte(form.Encode()))
	if rec.Code != 303 {
		t.Fatal("profile form failed", rec.Code, rec.Body.String())
	}
	profiles, err := store.Profiles(ctx, tenant.ID)
	if err != nil || len(profiles) != 1 {
		t.Fatal("profile form did not persist native profile", profiles, err)
	}
	form.Set("csrf", "wrong")
	rec = request("POST", base+"/ios/configurations", "application/x-www-form-urlencoded", []byte(form.Encode()))
	if rec.Code != 403 {
		t.Fatal("invalid CSRF accepted", rec.Code)
	}
	rec = request("GET", "/tenant/999999/ios/configurations", "", nil)
	if rec.Code != 404 {
		t.Fatal("unknown organization fell back to another scope", rec.Code)
	}
	devices, err := store.Devices(ctx, apple.Scope{TenantID: tenant.ID})
	if err != nil || len(devices) != 1 {
		t.Fatal("missing pending enrollment", devices, err)
	}
	form = url.Values{"csrf": {"console-test-token"}}
	rec = request("POST", base+"/ios/"+devices[0].ID+"/revoke", "application/x-www-form-urlencoded", []byte(form.Encode()))
	if rec.Code != 400 {
		t.Fatal("revocation accepted without acknowledging its effect", rec.Code)
	}
	form.Set("confirm_revoke", "yes")
	rec = request("POST", base+"/ios/"+devices[0].ID+"/revoke", "application/x-www-form-urlencoded", []byte(form.Encode()))
	if rec.Code != 303 {
		t.Fatal("revocation form failed", rec.Code, rec.Body.String())
	}
	d, err := store.Device(ctx, apple.Scope{TenantID: tenant.ID}, devices[0].ID)
	if err != nil || d.Status != "revoked" {
		t.Fatal("revocation not persisted", d, err)
	}
	t.Run("OIDC issuer settings reject unsafe URLs", func(t *testing.T) {
		oldCert, oldPasswd := h.ReenableCertAuth, h.ReenablePasswdAuth
		defer func() { h.ReenableCertAuth, h.ReenablePasswdAuth = oldCert, oldPasswd }()
		h.ReenableCertAuth, h.ReenablePasswdAuth = true, true

		before, err := m.GetAuthenticationSettings()
		if err != nil {
			t.Fatal(err)
		}
		for _, issuer := range []string{"http://issuer.example", "https://user:password@issuer.example", "https://issuer.example?q=x", "https://issuer.example/#fragment"} {
			form := url.Values{"csrf": {"console-test-token"}, "authentication-use-certificates": {"false"}, "authentication-allow-register": {"false"}, "authentication-use-oidc": {"true"}, "authentication-use-passwords": {"false"}, "authentication-oidc-provider": {"authelia"}, "authentication-oidc-server": {issuer}, "authentication-oidc-client-id": {"owned-client"}, "authentication-oidc-role": {"owned-role"}, "authentication-oidc-auto-create": {"false"}, "authentication-oidc-auto-approve": {"false"}}
			rec := request("POST", "/admin/authentication", "application/x-www-form-urlencoded", []byte(form.Encode()))
			if !strings.Contains(rec.Body.String(), "OIDC issuer must be an HTTPS URL") {
				t.Fatal("unsafe issuer configuration was not rejected", rec.Code)
			}
			if !h.ReenableCertAuth || !h.ReenablePasswdAuth {
				t.Fatal("invalid settings disabled emergency authentication overrides")
			}

			after, err := m.GetAuthenticationSettings()
			if err != nil || after.OIDCIssuerURL != before.OIDCIssuerURL || after.UseOIDC != before.UseOIDC || after.OIDCClientID != before.OIDCClientID {
				t.Fatal("invalid OIDC settings changed configuration", err)
			}
		}
	})
	exerciseConsolePermissions(t, h, e, ctx, tenant.ID, site.ID, profiles[0].ID)
	exerciseWindowsConsole(t, h, e, ctx, tenant.ID, site.ID)
	exerciseDesktopConsolePermissions(t, h, e, ctx, tenant.ID, site.ID)
	exerciseAuditConsole(t, h, e, ctx, tenant.ID, site.ID)
}

// seedExistingAppleSettings represents existing credentials only inside a disposable
// test schema. Production imports still reject synthetic certificates.
func seedExistingAppleSettings(t *testing.T, db *sql.DB, c apple.Settings) {
	t.Helper()
	secretKey := sha256.Sum256([]byte("openuem/apple/secrets/v1\x00" + strings.Repeat("k", 32)))
	blockCipher, err := aes.NewCipher(secretKey[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(blockCipher)
	if err != nil {
		t.Fatal(err)
	}
	seal := func(field string, value []byte) []byte {
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		return aead.Seal(nonce, nonce, value, []byte(fmt.Sprintf("%d/settings/%s", c.TenantID, field)))
	}
	_, err = db.Exec(`INSERT INTO mdm_apple_settings(tenant_id,public_url,organization,topic,push_expires_at,push_certificate,push_key,ca_certificate,ca_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, c.TenantID, c.PublicURL, c.Organization, c.Topic, c.PushExpiresAt, c.PushCertificate, seal("push_key", c.PushKey), c.CACertificate, seal("ca_key", c.CAKey))
	if err != nil {
		t.Fatal(err)
	}
}
