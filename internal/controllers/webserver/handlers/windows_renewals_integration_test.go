package handlers

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func exerciseWindowsRenewals(t *testing.T, h *Handler, ctx context.Context, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	t.Run("Windows renewal console preserves certificate continuity and scoped history", func(t *testing.T) {
		tenant, err := h.Model.Client.Tenant.Create().SetDescription("Synthetic renewal organization").Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = h.Model.CloneGlobalSettings(tenant.ID); err != nil {
			t.Fatal(err)
		}
		site, err := h.Model.Client.Site.Create().SetDescription("Synthetic renewal site").SetTenantID(tenant.ID).SetIsDefault(true).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		sibling, err := h.Model.Client.Site.Create().SetDescription("Synthetic renewal sibling").SetTenantID(tenant.ID).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		scope := access.Scope{TenantID: tenant.ID, SiteID: site.ID}
		admin := "renewal-organization-admin"
		for user, grant := range map[string]access.Grant{admin: {Role: access.TenantAdmin, Scope: access.Scope{TenantID: tenant.ID}}, "renewal-viewer": {Role: access.Viewer, Scope: scope}, "renewal-operator": {Role: access.Operator, Scope: scope}} {
			if _, err = h.Model.Client.User.Create().SetID(user).SetName(user).SetEmail(user + "@example.test").SetUse2fa(false).Save(ctx); err != nil {
				t.Fatal(err)
			}
			if err = h.Access.ReplaceGrants(ctx, "apple-console-admin", user, 0, []access.Grant{grant}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = h.Windows.InitializeAuthority(ctx, "apple-console-admin", tenant.ID, windows.AuthorityOptions{Organization: "Synthetic renewal organization", MinimumKeyBits: 2048, ValiditySeconds: 86400, RenewalSeconds: 86399}); err != nil {
			t.Fatal(err)
		}
		peer := newWindowsRenewalConsolePeer(t, h, ctx, scope)
		base := fmt.Sprintf("/tenant/%d/site/%d", tenant.ID, site.ID)
		devicePath := "/windows/" + peer.deviceID
		list := base + devicePath + "/renewals"
		empty := request(admin, "GET", list, nil)
		if empty.Code != 200 || !strings.Contains(empty.Body.String(), "No certificate renewals in this view.") {
			t.Fatal("empty renewal history unavailable", empty.Code)
		}
		first := peer.renew(t, h, ctx, scope)
		exerciseWindowsCertificateHealth(t, scope, sibling.ID, peer.deviceID, first, request, artifact)
		path := list + "/" + first.ID
		form := func() url.Values {
			return url.Values{"expected_revision": {"1"}, "resolution": {"Reviewed <script>synthetic replacement</script>"}, "confirm_cancel": {"yes"}}
		}
		for _, user := range []string{admin, "apple-console-admin", "renewal-viewer", "renewal-operator"} {
			w := request(user, "GET", base+devicePath, nil)
			if w.Code != 200 || strings.Contains(w.Body.String(), "Certificate renewals") != (user == admin || user == "apple-console-admin") {
				t.Fatal("renewal navigation ignored role", user, w.Code)
			}
		}
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant.ID), base} {
			for _, user := range []string{"renewal-viewer", "renewal-operator"} {
				for _, target := range []struct{ method, suffix string }{{"GET", ""}, {"GET", "/" + first.ID}, {"POST", "/" + first.ID + "/cancel"}} {
					w := request(user, target.method, prefix+devicePath+"/renewals"+target.suffix, form())
					if w.Code != 403 {
						t.Fatal("scoped role reached certificate history or cancellation", user, prefix, w.Code)
					}
				}
			}
		}
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant.ID)} {
			if w := request(admin, "GET", prefix+devicePath+"/renewals", nil); w.Code != 400 {
				t.Fatal("renewal history admitted all-sites selection", w.Code)
			}
		}
		for _, target := range []struct{ user, path string }{{"organization-admin", path}, {admin, fmt.Sprintf("/tenant/%d/site/%d", tenant.ID, sibling.ID) + devicePath + "/renewals/" + first.ID}, {admin, list + "/" + uuid.NewString()}, {admin, base + "/windows/" + uuid.NewString() + "/renewals/" + first.ID}} {
			if w := request(target.user, "GET", target.path, nil); w.Code != 404 {
				t.Fatal("foreign or unknown renewal details exposed", w.Code)
			}
			if w := request(target.user, "POST", target.path+"/cancel", form()); w.Code != 404 {
				t.Fatal("foreign or unknown renewal cancellation admitted", w.Code)
			}
		}
		for _, suffix := range []string{"?", "?offset=", "?offset=-1", "?offset=01", "?offset=100001", "?offset=1&offset=2", "?offset=0&tenant=1", "?query=secret", "?offset=%zz"} {
			if w := request(admin, "GET", list+suffix, nil); w.Code != 400 {
				t.Fatal("invalid renewal history query admitted", suffix, w.Code)
			}
		}
		for _, target := range []string{path + "?", path + "?offset=0", list + "/INVALID", list + "/" + strings.ToUpper(first.ID)} {
			if w := request(admin, "GET", target, nil); w.Code != 400 {
				t.Fatal("noncanonical renewal detail admitted", target, w.Code)
			}
		}
		detail, err := h.Windows.CertificateRenewalDetails(ctx, admin, scope, peer.deviceID, first.ID)
		if err != nil {
			t.Fatal(err)
		}
		pending := request(admin, "GET", path, nil)
		if pending.Code != 200 || pending.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("pending renewal detail unavailable or cacheable", pending.Code)
		}
		for _, want := range []string{"Pending confirmation", "Previous certificate", "Replacement certificate", detail.Source.FingerprintSHA256, detail.Replacement.FingerprintSHA256, `name="expected_revision" value="1"`, `name="csrf" value="console-test-token"`, path + "/cancel", "&lt;script&gt;peer&lt;/script&gt;"} {
			if !strings.Contains(pending.Body.String(), want) {
				t.Fatal("renewal detail lost reviewed metadata", want)
			}
		}
		for _, absent := range []string{"<script>peer</script>", "PRIVATE KEY", "owin1.", "APPAUTH", "CMSDER", "CSRDER"} {
			if strings.Contains(pending.Body.String(), absent) {
				t.Fatal("renewal detail exposed protected content", absent)
			}
		}
		artifact("windows-renewal-pending", pending)
		for _, bad := range []struct {
			field, value string
			status       int
		}{{"csrf", "wrong", 403}, {"confirm_cancel", "", 400}, {"expected_revision", "0", 400}, {"expected_revision", "01", 400}, {"expected_revision", "+1", 400}, {"expected_revision", "9223372036854775808", 400}, {"expected_revision", "2", 409}, {"resolution", "", 400}, {"resolution", " padded", 400}, {"resolution", "two\nlines", 400}, {"resolution", strings.Repeat("x", 321), 400}, {"tenant", "999", 400}} {
			f := form()
			f.Set(bad.field, bad.value)
			if w := request(admin, "POST", path+"/cancel", f); w.Code != bad.status {
				t.Fatal("invalid renewal mutation admitted", bad.field, w.Code)
			}
		}
		duplicate := form()
		duplicate.Add("resolution", "duplicate")
		if w := request(admin, "POST", path+"/cancel", duplicate); w.Code != 400 {
			t.Fatal("duplicate cancellation field admitted", w.Code)
		}
		if w := request(admin, "POST", path+"/cancel?offset=0", form()); w.Code != 400 {
			t.Fatal("query cancellation admitted", w.Code)
		}
		unchanged, err := h.Windows.CertificateRenewalDetails(ctx, admin, scope, peer.deviceID, first.ID)
		if err != nil || unchanged.Renewal.Phase != "pending" || unchanged.Renewal.Revision != 1 {
			t.Fatal("rejected form changed the pending certificate", err)
		}
		var candidateDER []byte
		if err = h.Model.DB.QueryRowContext(ctx, `SELECT certificate FROM mdm_windows_device_certificates WHERE id=$1`, first.RenewedCertificateID).Scan(&candidateDER); err != nil {
			t.Fatal(err)
		}
		candidate, err := x509.ParseCertificate(candidateDER)
		if err != nil {
			t.Fatal(err)
		}
		assertWindowsRenewalConsoleAccess(t, h, ctx, peer.certificate, true)
		assertWindowsRenewalConsoleAccess(t, h, ctx, candidate, true)
		if w := request(admin, "POST", path+"/cancel", form()); w.Code != 303 || w.Header().Get("Location") != path || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("renewal cancellation redirect failed", w.Code)
		}
		if w := request(admin, "POST", path+"/cancel", form()); w.Code != 409 {
			t.Fatal("stale cancellation repeated", w.Code)
		}
		canceled := request(admin, "GET", path, nil)
		if canceled.Code != 200 || !strings.Contains(canceled.Body.String(), "Replacement canceled") || !strings.Contains(canceled.Body.String(), "Reviewed &lt;script&gt;synthetic replacement&lt;/script&gt;") || strings.Contains(canceled.Body.String(), `name="confirm_cancel"`) || strings.Contains(canceled.Body.String(), "<script>synthetic replacement</script>") {
			t.Fatal("canceled renewal history lost safety or evidence", canceled.Code)
		}
		artifact("windows-renewal-canceled", canceled)
		assertWindowsRenewalConsoleAccess(t, h, ctx, peer.certificate, true)
		assertWindowsRenewalConsoleAccess(t, h, ctx, candidate, false)
		// Eleven genuine intents exercise the ten-row history boundary. No lifecycle
		// row, sealed document or production renewal window is rewritten for tests.
		for i := 0; i < 9; i++ {
			renewal := peer.renew(t, h, ctx, scope)
			if err = h.Windows.CancelCertificateRenewal(ctx, admin, scope, peer.deviceID, renewal.ID, 1, "Synthetic pagination history"); err != nil {
				t.Fatal(err)
			}
		}
		latest := peer.renew(t, h, ctx, scope)
		page := request(admin, "GET", list, nil)
		if page.Code != 200 || !strings.Contains(page.Body.String(), "Next renewals") || strings.Contains(page.Body.String(), "Previous renewals") || !strings.Contains(page.Body.String(), latest.ID) || strings.Contains(page.Body.String(), first.ID) {
			t.Fatal("renewal history first page is incorrect", page.Code)
		}
		artifact("windows-renewal-history", page)
		page = request(admin, "GET", list+"?offset=10", nil)
		if page.Code != 200 || strings.Contains(page.Body.String(), "Next renewals") || !strings.Contains(page.Body.String(), "Previous renewals") || !strings.Contains(page.Body.String(), first.ID) || strings.Contains(page.Body.String(), latest.ID) {
			t.Fatal("renewal history second page is incorrect", page.Code)
		}
		artifact("windows-renewal-history-page-two", page)
		runConsoleBrowserFixture(t, h, ctx, os.Getenv("OPENUEM_WINDOWS_RENEWAL_BROWSER_FIXTURE"), list)
	})
}
