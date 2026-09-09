package handlers

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/desktop"
)

// Exercise desktop routes on the real console router, session/role store and
// Ent schema used by TestNativeAppleConsoleRoutesWithPostgres.
func exerciseDesktopConsolePermissions(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenantID, siteID int) {
	t.Helper()
	store, err := desktop.NewStore(h.Model.DB, strings.Repeat("d", 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	h.Desktop = store
	h.PublicOrigin = "https://uem.example.test"
	adminID := "apple-console-admin"
	sm := h.SessionManager.Manager
	defer sm.Put(ctx, "uid", adminID)
	base := fmt.Sprintf("/tenant/%d/site/%d", tenantID, siteID)
	orgBase := fmt.Sprintf("/tenant/%d", tenantID)
	requestBody := func(user, method, path, contentType string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		sm.Put(ctx, "uid", user)
		req := httptest.NewRequest(method, path, bytes.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", contentType)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	request := func(user, method, path string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		if form == nil {
			form = url.Values{}
		}
		if method != "GET" && form.Get("csrf") == "" {
			form.Set("csrf", "console-test-token")
		}
		return requestBody(user, method, path, "application/x-www-form-urlencoded", []byte(form.Encode()))
	}
	writeArtifact := func(name string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if dir := os.Getenv("OPENUEM_DESKTOP_UI_ARTIFACTS"); dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name+".html"), rec.Body.Bytes(), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("desktop authority setup is scoped and uses the configured public origin", func(t *testing.T) {
		rec := request("organization-admin", "GET", orgBase+"/desktop/enrollment", nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Set up organization identity") {
			t.Fatal("organization setup form unavailable", rec.Code, rec.Body.String())
		}
		writeArtifact("desktop-setup", rec)
		for _, user := range []string{"scoped-viewer", "scoped-operator"} {
			rec = request(user, "GET", base+"/desktop/enrollment", nil)
			if rec.Code != 200 || strings.Contains(rec.Body.String(), "authority_key") {
				t.Fatal("scoped role sees certificate administration", user, rec.Code)
			}
			for _, prefix := range []string{"", orgBase, base} {
				rec = request(user, "POST", prefix+"/desktop/setup", url.Values{"authority_source": {"automatic"}, "organization": {"Escalation"}})
				if rec.Code != 403 {
					t.Fatal("role changed organization authority", user, prefix, rec.Code)
				}
			}
		}
		form := url.Values{"authority_source": {"automatic"}, "organization": {"Example <script>alert(1)</script> organization"}, "public_origin": {"https://attacker.example"}, "csrf": {"wrong"}}
		rec = request("organization-admin", "POST", orgBase+"/desktop/setup", form)
		if rec.Code != 403 {
			t.Fatal("authority setup accepted wrong CSRF", rec.Code)
		}
		form.Set("csrf", "console-test-token")
		h.PublicOrigin = ""
		rec = request("organization-admin", "POST", orgBase+"/desktop/setup", form)
		if rec.Code != 503 {
			t.Fatal("setup derived an origin from request input", rec.Code)
		}
		h.PublicOrigin = "https://uem.example.test"
		rec = request("organization-admin", "POST", orgBase+"/desktop/setup", form)
		if rec.Code != 303 || rec.Header().Get("Location") != orgBase+"/desktop/enrollment" {
			t.Fatal("authority setup failed", rec.Code, rec.Body.String())
		}
		authority, err := store.Authority(ctx, registry.Scope{TenantID: tenantID}, adminID)
		if err != nil || authority.PublicOrigin != h.PublicOrigin {
			t.Fatal("authority used an untrusted public address", err)
		}
		var encrypted string
		if err = h.Model.DB.QueryRowContext(ctx, `SELECT encrypted_key FROM uem_agent_authorities WHERE tenant_id=$1`, tenantID).Scan(&encrypted); err != nil {
			t.Fatal(err)
		}
		if encrypted == "" || strings.Contains(encrypted, "PRIVATE KEY") {
			t.Fatal("authority key is not encrypted at rest")
		}
		rec = request("organization-admin", "GET", orgBase+"/desktop/enrollment", nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "<script>alert(1)</script>") || strings.Contains(rec.Body.String(), encrypted) || strings.Contains(rec.Body.String(), "BEGIN PRIVATE KEY") {
			t.Fatal("authority rendering exposed unescaped text or private material", rec.Code)
		}
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "strict-origin" {
			t.Fatal("enrollment administration lacks response privacy headers")
		}
		for _, path := range []string{"/tenant/999999/desktop/enrollment", fmt.Sprintf("/tenant/%d/site/999999/desktop/enrollment", tenantID)} {
			if rec = request(adminID, "GET", path, nil); rec.Code != 404 {
				t.Fatal("unknown scope fell back to another organization or site", path, rec.Code)
			}
		}
	})
	otherTenant, err := h.Model.Client.Tenant.Create().SetDescription("Private desktop organization").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.Model.CloneGlobalSettings(otherTenant.ID); err != nil {
		t.Fatal(err)
	}
	otherSite, err := h.Model.Client.Site.Create().SetDescription("Private desktop site").SetTenantID(otherTenant.ID).SetIsDefault(true).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := h.Model.Client.Site.Create().SetDescription("Sibling desktop site").SetTenantID(tenantID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("desktop enterprise import errors do not expose uploaded secrets", func(t *testing.T) {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		for name, value := range map[string]string{"csrf": "console-test-token", "authority_source": "enterprise", "organization": "Enterprise"} {
			if err := writer.WriteField(name, value); err != nil {
				t.Fatal(err)
			}
		}
		secret := "invalid-private-key-secret-sentinel"
		for _, name := range []string{"authority_certificate", "authority_key"} {
			part, err := writer.CreateFormFile(name, name+".pem")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = part.Write([]byte(secret)); err != nil {
				t.Fatal(err)
			}
		}
		if err = writer.Close(); err != nil {
			t.Fatal(err)
		}
		rec := requestBody(adminID, "POST", fmt.Sprintf("/tenant/%d/desktop/setup", otherTenant.ID), writer.FormDataContentType(), body.Bytes())
		if rec.Code != 400 || strings.Contains(rec.Body.String(), secret) {
			t.Fatal("invalid enterprise import was accepted or disclosed its content", rec.Code)
		}
	})
	if _, err = store.Registry.EnsureAuthority(ctx, otherTenant.ID, "Private desktop organization", h.PublicOrigin, adminID, nil, nil); err != nil {
		t.Fatal(err)
	}
	invites := []*registry.Invitation{}
	identities := []*enrollment.Response{}
	tokens := []string{}
	for i, scope := range []registry.Scope{{TenantID: tenantID, SiteID: siteID}, {TenantID: tenantID, SiteID: sibling.ID}, {TenantID: otherTenant.ID, SiteID: otherSite.ID}} {
		invite, err := store.Registry.Invite(ctx, registry.InvitationOptions{Scope: scope, Platform: "windows", Architecture: "amd64", MaxUses: 2, ExpiresAt: time.Now().Add(time.Hour)}, adminID)
		if err != nil {
			t.Fatal(err)
		}
		invites = append(invites, invite)
		token := invite.URL[strings.LastIndex(invite.URL, "/")+1:]
		tokens = append(tokens, token)
		keys, err := enrollment.GenerateKeys()
		if err != nil {
			t.Fatal(err)
		}
		proof, err := keys.Request(token, "windows", "amd64", "Desktop fixture "+strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		identity, err := store.Registry.Claim(ctx, *proof)
		if err != nil {
			t.Fatal(err)
		}
		identities = append(identities, identity)
	}
	t.Run("desktop metadata and controls follow current session permissions", func(t *testing.T) {
		for _, path := range []string{"/desktop/enrollment", orgBase + "/desktop/enrollment", base + "/desktop/enrollment"} {
			rec := request("scoped-viewer", "GET", path, nil)
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Desktop fixture 0") {
				t.Fatal("viewer cannot read its desktop identities", path, rec.Code, rec.Body.String())
			}
			for _, forbidden := range append([]string{"Desktop fixture 1", "Desktop fixture 2", "Private desktop organization", "Revoke invitation", "Revoke identity", "BEGIN PRIVATE KEY"}, tokens...) {
				if strings.Contains(rec.Body.String(), forbidden) {
					t.Error("viewer response exposed a secret, foreign resource or mutation", forbidden)
				}
			}
			writeArtifact("desktop-viewer", rec)
		}
		rec := request("scoped-operator", "GET", base+"/desktop/enrollment", nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Revoke invitation") || strings.Contains(rec.Body.String(), "Revoke identity") {
			t.Fatal("operator controls do not match capabilities", rec.Code)
		}
		writeArtifact("desktop-operator", rec)
		rec = request("organization-admin", "GET", orgBase+"/desktop/enrollment", nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Desktop fixture 1") || !strings.Contains(rec.Body.String(), "Revoke identity") {
			t.Fatal("organization administrator lacks scoped controls", rec.Code)
		}
		writeArtifact("desktop-admin", rec)
		for _, path := range []string{fmt.Sprintf("/tenant/%d/desktop/enrollment", otherTenant.ID), fmt.Sprintf("/tenant/%d/site/%d/desktop/enrollment", tenantID, sibling.ID)} {
			if rec = request("scoped-viewer", "GET", path, nil); rec.Code != 404 {
				t.Fatal("foreign desktop scope was accessible", rec.Code)
			}
		}
	})
	t.Run("desktop revocation enforces scope capability CSRF and confirmation", func(t *testing.T) {
		form := url.Values{"confirm_revoke": {"yes"}}
		for _, prefix := range []string{"", orgBase, base} {
			for _, suffix := range []string{"/desktop/invitations/" + invites[0].ID + "/revoke", "/desktop/identities/" + identities[0].DeviceID + "/revoke"} {
				if rec := request("scoped-viewer", "POST", prefix+suffix, form); rec.Code != 403 {
					t.Fatal("viewer reached desktop revocation", prefix+suffix, rec.Code)
				}
			}
		}
		identityPath := base + "/desktop/identities/" + identities[0].DeviceID + "/revoke"
		if rec := request("scoped-operator", "POST", identityPath, form); rec.Code != 403 {
			t.Fatal("operator revoked an identity", rec.Code)
		}
		for _, invite := range invites[1:] {
			if rec := request("scoped-operator", "POST", base+"/desktop/invitations/"+invite.ID+"/revoke", form); rec.Code != 404 {
				t.Fatal("operator revoked another site's invitation", rec.Code)
			}
		}
		if rec := request("organization-admin", "POST", orgBase+"/desktop/identities/"+identities[2].DeviceID+"/revoke", form); rec.Code != 404 {
			t.Fatal("organization admin revoked another organization's identity", rec.Code)
		}
		for _, path := range []string{base + "/desktop/invitations/" + invites[0].ID + "/revoke", identityPath} {
			if rec := request("organization-admin", "GET", path, nil); rec.Code == 200 || rec.Code == 303 {
				t.Fatal("GET reached a revocation mutation", rec.Code)
			}
			if rec := request("organization-admin", "POST", path, nil); rec.Code != 400 {
				t.Fatal("revocation accepted without explicit confirmation", rec.Code)
			}
			if rec := request("organization-admin", "POST", path, url.Values{"csrf": {"wrong"}, "confirm_revoke": {"yes"}}); rec.Code != 403 {
				t.Fatal("revocation accepted wrong CSRF", rec.Code)
			}
		}
		var revoked bool
		if err = h.Model.DB.QueryRowContext(ctx, `SELECT revoked_at IS NOT NULL FROM uem_agent_identities WHERE id=$1`, identities[0].DeviceID).Scan(&revoked); err != nil || revoked {
			t.Fatal("denied requests changed device identity", err)
		}
		if rec := request("scoped-operator", "POST", base+"/desktop/invitations/"+invites[0].ID+"/revoke", form); rec.Code != 303 {
			t.Fatal("authorized invitation revocation failed", rec.Code, rec.Body.String())
		}
		if rec := request("organization-admin", "POST", identityPath, form); rec.Code != 303 {
			t.Fatal("authorized identity revocation failed", rec.Code, rec.Body.String())
		}
		var queued bool
		if err = h.Model.DB.QueryRowContext(ctx, `SELECT i.revoked_at IS NOT NULL, NOT q.desired_active AND q.revision>q.completed_revision FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id WHERE i.id=$1`, identities[0].DeviceID).Scan(&revoked, &queued); err != nil || !revoked || !queued {
			t.Fatal("revocation did not persist identity and command cleanup atomically", err)
		}
	})
	exerciseDesktopInvitationCreation(t, h, ctx, tenantID, siteID, sibling.ID, request, writeArtifact)
	exerciseMacConsole(t, h, ctx, tenantID, siteID, sibling.ID, request, writeArtifact)
	exerciseAppleUsers(t, h, ctx, tenantID, siteID, sibling.ID, request, writeArtifact)
	exerciseAppleFileVault(t, h, ctx, tenantID, siteID, sibling.ID, request, writeArtifact)
	exerciseAppleRecoveryLock(t, h, ctx, tenantID, siteID, sibling.ID, request, writeArtifact)
	exerciseAppleMacAdmin(t, h, ctx, tenantID, siteID, sibling.ID, request)
	exerciseAppleApplications(t, h, ctx, tenantID, siteID, sibling.ID, request)
	exerciseAppleFirewall(t, h, ctx, tenantID, siteID, request, writeArtifact)
	exerciseApplePlatformSSO(t, h, ctx, tenantID, siteID, request)
	exerciseAppleGatekeeper(t, h, ctx, tenantID, siteID, request)
	exerciseAppleSystemExtensions(t, h, ctx, tenantID, siteID, request)
	exerciseApplePrivacy(t, h, ctx, tenantID, siteID, request)
	exerciseApplePublicCertificates(t, h, ctx, tenantID, siteID, requestBody)
	exerciseADEPlatformSSORoutes(t, h, ctx, tenantID, siteID, sibling.ID, request)
	exerciseAppleProfileRevisions(t, h, ctx, tenantID, siteID, request)
	runDesktopBrowserFixture(t, h, ctx)
}

func TestDesktopCapabilitiesDenyUnrecognizedPathsAndMethods(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
		if _, ok := desktopCapability(method, "/desktop/setup"); ok {
			t.Fatal("unregistered method received a desktop capability")
		}
	}
	for _, path := range []string{"/desktop", "/desktop/setup/extra", "/desktop/identities/:id/update", "/desktop/invitations/:id/download"} {
		if _, ok := desktopCapability(http.MethodPost, path); ok {
			t.Fatal("unregistered path received a desktop capability")
		}
	}
}
