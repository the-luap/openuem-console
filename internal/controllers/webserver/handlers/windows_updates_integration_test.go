package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func exerciseWindowsUpdateConsole(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, deviceID string, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	t.Run("Windows update history requires live update permission and scoped cancellation", func(t *testing.T) {
		zero := 0
		policy := windows.UpdatePolicy{QualityDeferralDays: &zero}
		run, err := h.Windows.EnqueueUpdatePolicy(ctx, "scoped-operator", scope, deviceID, uuid.NewString(), "Synthetic <script>update policy</script>", policy, false, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		base := fmt.Sprintf("/tenant/%d/site/%d/windows/%s", scope.TenantID, scope.SiteID, deviceID)
		detailPath := base + "/updates/" + run.ID
		for _, user := range []string{"apple-console-admin", "organization-admin", "scoped-operator"} {
			for _, path := range []string{base + "/updates", detailPath} {
				w := request(user, "GET", path, nil)
				if w.Code != 200 || !strings.Contains(w.Body.String(), run.ID) || !strings.Contains(w.Body.String(), "Waiting for platform evidence") || strings.Contains(w.Body.String(), "<script>update policy</script>") || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("scoped update history failed", user, path, w.Code)
				}
			}
		}
		artifact("windows-update-runs", request("scoped-operator", "GET", base+"/updates", nil))
		artifact("windows-update-pending", request("scoped-operator", "GET", detailPath, nil))
		for _, path := range []string{base + "/updates", detailPath} {
			if w := request("scoped-viewer", "GET", path, nil); w.Code != 403 || strings.Contains(w.Body.String(), "update policy</script>") {
				t.Fatal("reader received protected update history", w.Code)
			}
		}
		if w := request("scoped-viewer", "POST", detailPath+"/cancel", url.Values{"confirm_cancel": {"yes"}}); w.Code != 403 {
			t.Fatal("reader canceled update intent", w.Code)
		}
		for _, suffix := range []string{"?offset=-1", "?offset=100001", "?offset=1&offset=2", "?offset=&offset=1", "?offset=01"} {
			if w := request("scoped-operator", "GET", base+"/updates"+suffix, nil); w.Code != 400 {
				t.Fatal("unbounded update history page admitted", w.Code)
			}
		}
		if w := request("scoped-operator", "GET", base+"/updates?offset=1", nil); w.Code != 200 || strings.Contains(w.Body.String(), run.ID) {
			t.Fatal("update history offset ignored", w.Code)
		}
		for _, id := range []string{"invalid", uuid.NewString()} {
			want := 404
			if id == "invalid" {
				want = 400
			}
			if w := request("scoped-operator", "GET", base+"/updates/"+id, nil); w.Code != want {
				t.Fatal("invalid or foreign run admitted", w.Code)
			}
		}
		sibling, err := h.Model.Client.Site.Create().SetDescription("Windows update sibling").SetTenantID(scope.TenantID).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		foreign := fmt.Sprintf("/tenant/%d/site/%d/windows/%s/updates/%s", scope.TenantID, sibling.ID, deviceID, run.ID)
		if w := request("organization-admin", "GET", foreign, nil); w.Code != 404 {
			t.Fatal("sibling site read update intent", w.Code)
		}
		if w := request("organization-admin", "POST", foreign+"/cancel", url.Values{"confirm_cancel": {"yes"}}); w.Code != 404 {
			t.Fatal("sibling site canceled update intent", w.Code)
		}
		if _, err := h.Model.DB.ExecContext(ctx, `CREATE FUNCTION fail_windows_update_console_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic private update audit error'; END $$; CREATE TRIGGER fail_windows_update_console_audit BEFORE INSERT ON mdm_windows_update_audit FOR EACH ROW EXECUTE FUNCTION fail_windows_update_console_audit()`); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{base + "/updates", detailPath} {
			if w := request("scoped-operator", "GET", path, nil); w.Code != 503 || strings.Contains(w.Body.String(), "update audit error") || strings.Contains(w.Body.String(), run.ID) {
				t.Fatal("unaudited update payload or internal error escaped", w.Code)
			}
		}
		if w := request("scoped-operator", "POST", detailPath+"/cancel", url.Values{"confirm_cancel": {"yes"}}); w.Code != 503 {
			t.Fatal("unaudited update cancellation committed", w.Code)
		}
		if _, err := h.Model.DB.ExecContext(ctx, `DROP TRIGGER fail_windows_update_console_audit ON mdm_windows_update_audit; DROP FUNCTION fail_windows_update_console_audit()`); err != nil {
			t.Fatal(err)
		}
		if d, err := h.Windows.UpdateRunDetails(ctx, "scoped-operator", scope, deviceID, run.ID); err != nil || d.Phase != "preflight_pending" {
			t.Fatal("failed cancellation changed update state", err)
		}
		for _, form := range []url.Values{{}, {"confirm_cancel": {"yes", "yes"}}, {"confirm_cancel": {"yes"}, "revision": {"1"}}} {
			if w := request("scoped-operator", "POST", detailPath+"/cancel", form); w.Code != 400 {
				t.Fatal("ambiguous cancellation form admitted", w.Code)
			}
		}
		if w := request("scoped-operator", "POST", detailPath+"/cancel", url.Values{"confirm_cancel": {"yes"}, "csrf": {"wrong"}}); w.Code != 403 {
			t.Fatal("cancellation accepted invalid CSRF", w.Code)
		}
		if w := request("scoped-operator", "POST", detailPath+"/cancel", url.Values{"confirm_cancel": {"yes"}}); w.Code != 303 || w.Header().Get("Location") != detailPath {
			t.Fatal("confirmed cancellation failed", w.Code)
		}
		if w := request("scoped-operator", "GET", detailPath, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Undelivered steps canceled") || strings.Contains(w.Body.String(), "name=\"confirm_cancel\"") {
			t.Fatal("canceled update history incorrect", w.Code)
		}
		if w := request("scoped-operator", "POST", detailPath+"/cancel", url.Values{"confirm_cancel": {"yes"}}); w.Code != 409 {
			t.Fatal("terminal cancellation did not report conflict", w.Code)
		}
		if os.Getenv("OPENUEM_DESKTOP_BROWSER_FIXTURE") != "" {
			// Leave only synthetic queue state for manual loopback form acceptance.
			if _, err := h.Windows.EnqueueUpdatePolicy(ctx, "scoped-operator", scope, deviceID, uuid.NewString(), "Browser acceptance pending policy", policy, false, time.Hour); err != nil {
				t.Fatal(err)
			}
		}
	})
}
