package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/pem"
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
	"github.com/invopop/ctxi18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/models"
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
	if _, err = m.Client.User.Create().SetID("apple-console-admin").SetName("Console Admin").SetEmail("admin@example.test").SetUse2fa(false).Save(ctx); err != nil {
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
	if err = ctxi18n.LoadWithDefault(locales.Content, "en"); err != nil {
		t.Fatal(err)
	}
	ctx, err = ctxi18n.WithLocale(ctx, "en")
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	sm.Put(ctx, "uid", "apple-console-admin")
	releases := t.TempDir()
	if err = os.WriteFile(filepath.Join(releases, "latest.json"), []byte(`{"Version":"0.11.0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	h := &Handler{Model: m, Apple: store, SessionManager: &sessions.SessionManager{Manager: sm}, Version: "0.11.0", ServerReleasesFolder: releases}
	e := echo.New()
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error { c.Set("csrf", "console-test-token"); return next(c) }
	})
	h.RegisterApple(e)
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
	cert := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "Test APNs", ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: "com.apple.mgmt.console-test"}}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
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
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "credentials saved") {
		t.Fatal("setup form failed", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "BEGIN PRIVATE KEY") {
		t.Fatal("private key leaked in setup response")
	}
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
}
