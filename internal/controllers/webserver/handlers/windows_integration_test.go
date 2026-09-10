package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func exerciseWindowsConsole(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	t.Helper()
	store, err := windows.NewStoreWithMasterKey(h.Model.DB, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("w", 32))))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	h.Windows = store
	h.WindowsOptions = windows.EnrollmentOptions{ManagementURL: "https://uem.example.test/mdm/windows/syncml", ProviderID: "OpenUEM", DisplayName: "OpenUEM Windows Management"}
	admin := "apple-console-admin"
	sm := h.SessionManager.Manager
	defer sm.Put(ctx, "uid", admin)
	base := fmt.Sprintf("/tenant/%d/site/%d", tenant, site)
	orgBase := fmt.Sprintf("/tenant/%d", tenant)
	scope := access.Scope{TenantID: tenant, SiteID: site}
	request := func(user, method, path string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		sm.Put(ctx, "uid", user)
		if form == nil {
			form = url.Values{}
		}
		if method == "POST" && form.Get("csrf") == "" {
			form.Set("csrf", "console-test-token")
		}
		r := httptest.NewRequest(method, path, strings.NewReader(form.Encode())).WithContext(ctx)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		return w
	}
	artifact := func(name string, w *httptest.ResponseRecorder) {
		t.Helper()
		if dir := os.Getenv("OPENUEM_WINDOWS_UI_ARTIFACTS"); dir != "" {
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name+".html"), w.Body.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("Windows setup and invitation routes enforce actual roles", func(t *testing.T) {
		for _, user := range []string{admin, "organization-admin", "scoped-operator", "scoped-viewer"} {
			w := request(user, "GET", base+"/windows", nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "Native Windows management") {
				t.Fatal("Windows navigation unavailable", user, w.Code)
			}
			if user == "scoped-viewer" || user == "scoped-operator" {
				if strings.Contains(w.Body.String(), "name=\"key_bits\"") {
					t.Fatal("CA mutation form leaked to scoped role")
				}
				for _, prefix := range []string{"", orgBase, base} {
					if w := request(user, "POST", prefix+"/windows/setup", url.Values{"confirm_setup": {"yes"}}); w.Code != 403 {
						t.Fatal("Windows CA escalation admitted", user, w.Code)
					}
				}
			}
		}
		artifact("windows-setup", request("organization-admin", "GET", base+"/windows", nil))
		form := url.Values{"organization": {"Windows <script>private</script> organization"}, "key_bits": {"2048"}, "validity_days": {"365"}, "confirm_setup": {"yes"}, "csrf": {"wrong"}}
		if w := request("organization-admin", "POST", orgBase+"/windows/setup", form); w.Code != 403 {
			t.Fatal("CA mutation admitted invalid CSRF", w.Code)
		}
		form.Set("csrf", "console-test-token")
		if w := request("organization-admin", "POST", orgBase+"/windows/setup", form); w.Code != 303 {
			t.Fatal("CA form failed", w.Code)
		}
		if w := request("organization-admin", "POST", orgBase+"/windows/setup", form); w.Code != 409 {
			t.Fatal("CA was silently replaced", w.Code)
		}
		if w := request("organization-admin", "GET", base+"/windows", nil); w.Code != 200 || strings.Contains(w.Body.String(), "<script>private</script>") || strings.Contains(w.Body.String(), "PRIVATE KEY") {
			t.Fatal("CA output was not escaped/protected")
		}
		for _, path := range []string{"/tenant/999999/windows", fmt.Sprintf("/tenant/%d/site/999999/windows", tenant)} {
			if w := request(admin, "GET", path, nil); w.Code != 404 {
				t.Fatal("unknown Windows scope fell back to default", w.Code)
			}
		}
		for _, path := range []string{base + "/windows/invitations", base + "/windows/invitations/" + uuid.NewString() + "/revoke", base + "/windows/" + uuid.NewString() + "/revoke"} {
			if w := request("scoped-viewer", "POST", path, nil); w.Code != 403 {
				t.Fatal("viewer reached Windows mutation", w.Code)
			}
		}
	})
	t.Run("Windows one-time credentials never return on GET", func(t *testing.T) {
		for _, bad := range []url.Values{{"username": {"user@example.test"}, "hours": {"25"}}, {"username": {"user@example.test", "second@example.test"}, "hours": {"1"}}, {"username": {"user@example.test"}, "hours": {"1"}, "tenant": {"2"}}} {
			if w := request("scoped-operator", "POST", base+"/windows/invitations", bad); w.Code != 400 {
				t.Fatal("invalid Windows form admitted", w.Code)
			}
		}
		w := request("scoped-operator", "POST", base+"/windows/invitations", url.Values{"username": {"native@example.test"}, "hours": {"1"}})
		if w.Code != 200 || !strings.Contains(w.Body.String(), "owin1.") || !strings.Contains(w.Body.String(), "https://uem.example.test") {
			t.Fatal("credential creation form failed", w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Location") != "" || w.Header().Get("Referrer-Policy") != "strict-origin" {
			t.Fatal("enrollment password response can be cached or redirected")
		}
		created, err := store.EnrollmentInvitations(ctx, admin, scope, 0, 25)
		if err != nil || len(created) != 1 || !strings.Contains(w.Body.String(), created[0].ID) {
			t.Fatal("new invitation is absent from the creation response's list")
		}
		artifact("windows-credential", w)
		w = request("scoped-operator", "GET", base+"/windows", nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), "owin1.") || !strings.Contains(w.Body.String(), "native@example.test") {
			t.Fatal("one-time credential reappeared or invitation missing", w.Code)
		}
		w = request("scoped-viewer", "GET", base+"/windows", nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), "native@example.test") || strings.Contains(w.Body.String(), "Create one-device invitation") {
			t.Fatal("reader saw enrollment account metadata")
		}
		invites, err := store.EnrollmentInvitations(ctx, admin, scope, 0, 25)
		if err != nil || len(invites) != 1 {
			t.Fatal("credential creation did not persist once", err)
		}
		if w := request("scoped-operator", "POST", base+"/windows/invitations/"+invites[0].ID+"/revoke", nil); w.Code != 400 {
			t.Fatal("invitation revoked without confirmation")
		}
		if w := request("scoped-operator", "POST", base+"/windows/invitations/"+invites[0].ID+"/revoke", url.Values{"confirm_revoke": {"yes"}}); w.Code != 303 {
			t.Fatal("invitation revocation failed", w.Code)
		}
		for _, suffix := range []string{"?devices_offset=-1", "?devices_offset=100001", "?devices_offset=1&devices_offset=2", "?q=" + strings.Repeat("x", 129)} {
			if w := request(admin, "GET", base+"/windows"+suffix, nil); w.Code != 400 {
				t.Fatal("invalid Windows page admitted", w.Code)
			}
		}
	})
	// Synthetic database-only device fixture: no host enrollment or device
	// command. Production transport proof is covered by the Windows TLS suite.
	invitation, _, err := store.CreateEnrollmentInvitation(ctx, admin, scope, "device@example.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	deviceID, certID := uuid.NewString(), uuid.NewString()
	a, err := store.EnrollmentAuthority(ctx, admin, tenant)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_windows_devices(id,tenant_id,site_id,invitation_id,reported_device_id,device_name,enrollment_type,os_edition,os_version,application_version) VALUES($1,$2,$3,$4,'SYNTHETIC-ID','Synthetic <script>Windows</script>','Device',4,'10.0.26100.1','10.0.26100.1');`, deviceID, tenant, site, invitation.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_windows_device_certificates(id,device_id,tenant_id,site_id,authority_id,certificate,fingerprint,public_key_fingerprint,serial,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,'synthetic certificate',decode(repeat('01',32),'hex'),decode(repeat('02',32),'hex'),'serial',clock_timestamp(),clock_timestamp()+INTERVAL '1 day')`, certID, deviceID, tenant, site, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_windows_enrollments(invitation_id,tenant_id,site_id,device_id,certificate_id,request_digest,configuration_digest,encrypted_provisioning,encrypted_auth) VALUES($1,$2,$3,$4,$5,decode(repeat('01',32),'hex'),decode(repeat('02',32),'hex'),decode(repeat('03',30),'hex'),decode(repeat('04',30),'hex'))`, invitation.ID, tenant, site, deviceID, certID)
	if err != nil {
		t.Fatal(err)
	}
	exerciseWindowsRingConsole(t, h, ctx, scope, request, artifact)
	exerciseWindowsAssignmentConsole(t, h, ctx, scope, deviceID, request, artifact)
	exerciseWindowsScheduleConsole(t, h, ctx, scope, deviceID, request, artifact)
	exerciseWindowsUpdateConsole(t, h, ctx, scope, deviceID, request, artifact)
	exerciseWindowsCSPConsole(t, h, ctx, scope, request, artifact)
	exerciseWindowsCSPForms(t, h, ctx, scope, deviceID, request, artifact)
	runConsoleBrowserFixture(t, h, ctx, os.Getenv("OPENUEM_WINDOWS_RING_BROWSER_FIXTURE"), base+"/windows/update-rings/new")
	runConsoleBrowserFixture(t, h, ctx, os.Getenv("OPENUEM_WINDOWS_POLICY_BROWSER_FIXTURE"), base+"/windows/"+deviceID+"/updates/new")
	t.Run("Windows device views and revocation are scoped", func(t *testing.T) {
		for _, path := range []string{base + "/devices?platform=windows", orgBase + "/devices?platform=windows", base + "/devices?q=synthetic"} {
			w := request("organization-admin", "GET", path, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), base+"/windows/"+deviceID) || !strings.Contains(w.Body.String(), "Native MDM: Certificate issued") {
				t.Fatal("native identity missing from unified inventory", path, w.Code)
			}
			if !strings.Contains(path, "q=") && !strings.Contains(w.Body.String(), "Finance Windows") {
				t.Fatal("native inventory replaced the separate agent identity")
			}
		}
		if w := request("scoped-viewer", "GET", base+"/devices?platform=windows", nil); w.Code != 200 || !strings.Contains(w.Body.String(), deviceID) {
			t.Fatal("scoped reader lost native inventory", w.Code)
		}
		if w := request("organization-admin", "GET", base+"/devices?platform=linux", nil); w.Code != 200 || strings.Contains(w.Body.String(), deviceID) {
			t.Fatal("native Windows inventory ignored the platform filter")
		}
		sibling, err := h.Model.Client.Site.Create().SetDescription("Native Windows sibling").SetTenantID(tenant).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		siblingBase := fmt.Sprintf("/tenant/%d/site/%d", tenant, sibling.ID)
		for _, path := range []string{siblingBase + "/windows", siblingBase + "/devices?platform=windows"} {
			if w := request("organization-admin", "GET", path, nil); w.Code != 200 || strings.Contains(w.Body.String(), deviceID) {
				t.Fatal("native identity leaked into sibling inventory", w.Code)
			}
		}
		if w := request("organization-admin", "GET", siblingBase+"/windows/"+deviceID, nil); w.Code != 404 {
			t.Fatal("sibling site read native details", w.Code)
		}
		if w := request("organization-admin", "POST", siblingBase+"/windows/"+deviceID+"/revoke", url.Values{"confirm_revoke": {"yes"}}); w.Code != 404 {
			t.Fatal("sibling site revoked native identity", w.Code)
		}
		for _, user := range []string{admin, "organization-admin", "scoped-operator", "scoped-viewer"} {
			w := request(user, "GET", base+"/windows/"+deviceID, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), deviceID) || strings.Contains(w.Body.String(), "<script>Windows</script>") {
				t.Fatal("Windows detail escaped/scope boundary failed", user, w.Code)
			}
			if (user == "scoped-viewer" || user == "scoped-operator") && strings.Contains(w.Body.String(), "Confirm device access revocation") {
				t.Fatal("device revocation form leaked")
			}
		}
		artifact("windows-device", request("organization-admin", "GET", base+"/windows/"+deviceID, nil))
		artifact("windows-devices", request("scoped-operator", "GET", base+"/windows", nil))
		if w := request("scoped-operator", "POST", base+"/windows/"+deviceID+"/revoke", url.Values{"confirm_revoke": {"yes"}}); w.Code != 403 {
			t.Fatal("operator revoked Windows identity")
		}
		if w := request("organization-admin", "POST", base+"/windows/"+deviceID+"/revoke", nil); w.Code != 400 {
			t.Fatal("device access revoked without confirmation")
		}
		if w := request("organization-admin", "POST", base+"/windows/"+deviceID+"/revoke", url.Values{"confirm_revoke": {"yes"}}); w.Code != 303 {
			t.Fatal("Windows device revocation failed", w.Code)
		}
		if d, err := store.Device(ctx, admin, scope, deviceID); err != nil || d.RevokedAt == nil {
			t.Fatal("device revocation not persisted", err)
		}
		if w := request("scoped-operator", "GET", base+"/windows/"+deviceID+"/updates/new", nil); w.Code != 409 {
			t.Fatal("revoked device admitted a new policy form", w.Code)
		}
		form := windowsPolicyTestForm()
		form.Set("confirm_policy", "yes")
		if w := request("scoped-operator", "POST", base+"/windows/"+deviceID+"/updates/create", form); w.Code != 409 {
			t.Fatal("revoked device admitted new policy work", w.Code)
		}
		if w := request("scoped-viewer", "GET", base+"/devices?platform=windows", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Native MDM: Access revoked") {
			t.Fatal("unified inventory lost revocation history", w.Code)
		}
	})
	for _, route := range e.Routes() {
		if _, ok := windowsCapability(route.Method, route.Path); ok {
			if route.Method != http.MethodGet && route.Method != http.MethodPost {
				t.Fatal("unexpected Windows mutation method")
			}
		}
	}
}
