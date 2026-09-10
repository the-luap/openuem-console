package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func exerciseWindowsUnenrollmentRequests(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	base := fmt.Sprintf("/tenant/%d/site/%d", scope.TenantID, scope.SiteID)
	admin := "organization-admin"
	draft := func() url.Values {
		return url.Values{"request_key": {uuid.NewString()}, "hours": {"24"}, "reason": {"Retire <script>synthetic enrollment</script>"}}
	}
	read := func(device, id string) *windows.UnenrollmentRequestDetail {
		t.Helper()
		d, err := h.Windows.UnenrollmentRequestDetails(ctx, admin, scope, device, id)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	create := func(device string, form url.Values) string {
		t.Helper()
		form.Set("confirm_disconnect", "yes")
		w := request(admin, "POST", base+"/windows/"+device+"/disconnections/create", form)
		if w.Code != 303 {
			t.Fatal("disconnection creation failed", w.Code, w.Body.String())
		}
		id := w.Header().Get("Location")
		id = id[strings.LastIndex(id, "/")+1:]
		return id
	}
	cancel := func(device, id string) {
		t.Helper()
		d := read(device, id)
		w := request(admin, "POST", base+"/windows/"+device+"/disconnections/"+id+"/cancel", url.Values{"expected_revision": {fmt.Sprint(d.Command.Revision)}, "confirm_cancel": {"yes"}})
		if w.Code != 303 {
			t.Fatal("disconnection cancellation failed", w.Code)
		}
	}
	t.Run("Windows disconnection forms preserve scope intent and cancellation", func(t *testing.T) {
		device, _, disconnect := windowsConsoleQueuedPeer(t, h, ctx, scope)
		devicePath := "/windows/" + device
		list := base + devicePath + "/disconnections"
		if w := request(admin, "GET", list, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "No disconnection requests in this view.") {
			t.Fatal("empty disconnection history unavailable", w.Code)
		}
		for _, user := range []string{admin, "apple-console-admin", "scoped-operator", "scoped-viewer"} {
			w := request(user, "GET", base+devicePath, nil)
			if w.Code != 200 || strings.Contains(w.Body.String(), "Windows disconnections") != (user == admin || user == "apple-console-admin") {
				t.Fatal("disconnection entry ignored role", user, w.Code)
			}
		}
		form := draft()
		preview := request(admin, "POST", list+"/preview", form)
		if preview.Code != 200 || !strings.Contains(preview.Body.String(), "This preview has not queued a command.") || !strings.Contains(preview.Body.String(), "&lt;script&gt;synthetic enrollment&lt;/script&gt;") {
			t.Fatal("disconnection preview lost meaning or escaping", preview.Code)
		}
		history, err := h.Windows.UnenrollmentRequests(ctx, admin, scope, device, 0, 10)
		if err != nil || len(history) != 0 {
			t.Fatal("preview queued work", err)
		}
		artifact("windows-disconnection-preview", preview)
		if w := request(admin, "POST", list+"/create", form); w.Code != 400 {
			t.Fatal("creation lacked explicit confirmation", w.Code)
		}
		for key, values := range map[string][]string{"hours": {"0", "169", "01", "1.5", "+1"}, "request_key": {"invalid", uuid.Nil.String()}, "reason": {"", " leading", "trailing ", "two\nlines", strings.Repeat("x", 321)}} {
			for _, value := range values {
				bad := draft()
				bad.Set(key, value)
				if w := request(admin, "POST", list+"/preview", bad); w.Code != 400 {
					t.Fatal("invalid disconnection draft admitted", key, w.Code)
				}
			}
		}
		for _, bad := range []url.Values{
			{"request_key": {form.Get("request_key")}, "hours": {"24", "24"}, "reason": {"Reason"}},
			{"request_key": {form.Get("request_key")}, "hours": {"24"}, "reason": {"Reason"}, "provider_id": {"Other"}},
			{"request_key": {form.Get("request_key")}, "hours": {"24"}, "reason": {"Reason"}, "csrf": {"wrong"}},
		} {
			if w := request(admin, "POST", list+"/preview", bad); w.Code != 400 && w.Code != 403 {
				t.Fatal("ambiguous or forged draft admitted", w.Code)
			}
		}

		// A preview does not preserve permission to create after a grant change.
		changing := "disconnection-admin-" + uuid.NewString()
		if _, err := h.Model.Client.User.Create().SetID(changing).SetName("Synthetic disconnection administrator").SetEmail(changing + "@example.test").SetUse2fa(false).Save(ctx); err != nil {
			t.Fatal(err)
		}
		if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", changing, 0, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: scope.TenantID}}}); err != nil {
			t.Fatal(err)
		}
		pending := draft()
		if w := request(changing, "POST", list+"/preview", pending); w.Code != 200 {
			t.Fatal("authorized preview unavailable", w.Code)
		}
		principal, err := h.Access.Principal(ctx, changing)
		if err != nil {
			t.Fatal(err)
		}
		if err = h.Access.ReplaceGrants(ctx, "apple-console-admin", changing, principal.Revision, []access.Grant{{Role: access.Viewer, Scope: scope}}); err != nil {
			t.Fatal(err)
		}
		pending.Set("confirm_disconnect", "yes")
		if w := request(changing, "POST", list+"/create", pending); w.Code != 403 {
			t.Fatal("preview preserved revoked creation rights", w.Code)
		}
		id := create(device, form)
		path := list + "/" + id
		if replay := create(device, form); replay != id {
			t.Fatal("exact form retry duplicated request")
		}
		changed := draft()
		changed.Set("request_key", form.Get("request_key"))
		changed.Set("reason", "Different retirement")
		changed.Set("confirm_disconnect", "yes")
		if w := request(admin, "POST", list+"/create", changed); w.Code != 409 {
			t.Fatal("changed form reused request key", w.Code)
		}
		if w := request(admin, "GET", list+"/new", nil); w.Code != 303 || !strings.HasSuffix(w.Header().Get("Location"), "/"+id) {
			t.Fatal("new form failed to reveal existing unresolved request", w.Code)
		}
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", scope.TenantID), base} {
			for _, user := range []string{"scoped-operator", "scoped-viewer"} {
				for _, target := range []struct{ method, suffix string }{{"GET", ""}, {"GET", "/new"}, {"GET", "/" + id}, {"POST", "/preview"}, {"POST", "/create"}, {"POST", "/" + id + "/cancel"}, {"POST", "/" + id + "/release"}} {
					if w := request(user, target.method, prefix+devicePath+"/disconnections"+target.suffix, draft()); w.Code != 403 {
						t.Fatal("unprivileged lifecycle route admitted", user, target, w.Code)
					}
				}
			}
		}
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", scope.TenantID)} {
			if w := request(admin, "GET", prefix+devicePath+"/disconnections", nil); w.Code != 400 {
				t.Fatal("all-sites lifecycle read admitted", w.Code)
			}
		}
		sibling, err := h.Model.Client.Site.Create().SetDescription("Disconnection request sibling").SetTenantID(scope.TenantID).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, wrong := range []string{fmt.Sprintf("/tenant/%d/site/%d", scope.TenantID, sibling.ID) + devicePath + "/disconnections/" + id, list + "/" + uuid.NewString()} {
			if w := request(admin, "GET", wrong, nil); w.Code != 404 {
				t.Fatal("unknown or sibling request exposed", w.Code)
			}
			if w := request(admin, "POST", wrong+"/cancel", url.Values{"expected_revision": {"1"}, "confirm_cancel": {"yes"}}); w.Code != 404 {
				t.Fatal("cancellation crossed request scope", w.Code)
			}
		}

		for _, target := range []struct {
			method, path string
			form         url.Values
		}{
			{"GET", path, nil},
			{"POST", path + "/cancel", url.Values{"expected_revision": {"1"}, "confirm_cancel": {"yes"}}},
			{"POST", path + "/release", url.Values{"expected_revision": {"1"}, "resolution": {"Reviewed"}, "confirm_release": {"yes"}}},
		} {
			if w := request("renewal-organization-admin", target.method, target.path, target.form); w.Code != 404 {
				t.Fatal("foreign organization reached disconnection evidence", w.Code)
			}
		}
		for _, query := range []string{"?", "?offset=", "?offset=-1", "?offset=01", "?offset=1&offset=2", "?offset=0&secret=x", "?query=x"} {
			if w := request(admin, "GET", list+query, nil); w.Code != 400 {
				t.Fatal("ambiguous history query admitted", query, w.Code)
			}
		}
		for _, query := range []string{"?", "?offset=0", "?&"} {
			if w := request(admin, "GET", path+query, nil); w.Code != 400 {
				t.Fatal("detail accepted query parameters", query, w.Code)
			}
		}
		for _, form := range []url.Values{{"expected_revision": {"1"}}, {"expected_revision": {"01"}, "confirm_cancel": {"yes"}}, {"expected_revision": {"1", "1"}, "confirm_cancel": {"yes"}}, {"expected_revision": {"1"}, "confirm_cancel": {"yes"}, "csrf": {"wrong"}}} {
			if w := request(admin, "POST", path+"/cancel", form); w.Code != 400 && w.Code != 403 {
				t.Fatal("unreviewed or ambiguous cancellation admitted", w.Code)
			}
		}
		if w := request(admin, "POST", path+"/cancel?expected_revision=1", url.Values{"expected_revision": {"1"}, "confirm_cancel": {"yes"}}); w.Code != 400 {
			t.Fatal("cancellation query bypassed body", w.Code)
		}
		if w := request(admin, "POST", path+"/cancel", url.Values{"expected_revision": {"2"}, "confirm_cancel": {"yes"}}); w.Code != 409 {
			t.Fatal("stale cancellation revision admitted", w.Code)
		}
		cancel(device, id)
		if read(device, id).Command.Phase != "canceled" {
			t.Fatal("cancellation missing")
		}
		for n := 0; n < 10; n++ {
			cancel(device, create(device, draft()))
		}
		page := request(admin, "GET", list, nil)
		older := request(admin, "GET", list+"?offset=10", nil)
		if page.Code != 200 || older.Code != 200 || strings.Count(page.Body.String(), ">Open request ") != 10 || strings.Count(older.Body.String(), ">Open request ") != 1 || !strings.Contains(page.Body.String(), "Next requests") || !strings.Contains(older.Body.String(), id) {
			t.Fatal("protected request paging failed")
		}
		artifact("windows-disconnection-history", page)
		disconnect()
		if replay := create(device, form); replay != id {
			t.Fatal("retirement broke exact intent retry")
		}
		if w := request(admin, "GET", list+"/new", nil); w.Code != 409 {
			t.Fatal("retired device exposed creation form", w.Code)
		}
		w := request(admin, "GET", path, nil)
		for _, want := range []string{"Device disconnection reported", "does not establish which request or person", "Canceled before delivery"} {
			if !strings.Contains(w.Body.String(), want) {
				t.Fatal("independent report attribution lost", want)
			}
		}
		if strings.Contains(w.Body.String(), `name="confirm_release"`) || strings.Contains(w.Body.String(), `name="confirm_disconnect"`) {
			t.Fatal("retired identity offered further management")
		}
	})
	t.Run("Windows disconnection review retains protocol evidence", func(t *testing.T) {
		paths := map[string]string{}
		for _, status := range []string{"", "200", "202", "500"} {
			device, exchange, disconnect := windowsConsoleQueuedPeer(t, h, ctx, scope)
			id := create(device, draft())
			path := base + "/windows/" + device + "/disconnections/" + id
			result := exchange(id, status)
			w := request(admin, "GET", path, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `name="confirm_release"`) || strings.Contains(w.Body.String(), `name="confirm_cancel"`) {
				t.Fatal("delivered request exposed wrong lifecycle actions", status, w.Code)
			}
			artifact("windows-disconnection-status-"+status, w)
			paths["status_"+status] = path
			review := url.Values{"expected_revision": {strconv.FormatInt(result.Command.Revision, 10)}, "resolution": {"Investigated <script>missing report</script>"}, "confirm_release": {"yes"}}
			for _, change := range []func(url.Values){func(f url.Values) { f.Del("confirm_release") }, func(f url.Values) { f.Set("csrf", "wrong") }, func(f url.Values) { f.Set("resolution", " ") }, func(f url.Values) { f["expected_revision"] = []string{"2", "2"} }} {
				bad := url.Values{}
				for key, values := range review {
					bad[key] = append([]string{}, values...)
				}
				change(bad)
				if response := request(admin, "POST", path+"/release", bad); response.Code != 400 && response.Code != 403 {
					t.Fatal("unreviewed or ambiguous release admitted", response.Code)
				}
			}
			// An audit failure must not partially abort the live session or release it.
			if _, err := h.Model.DB.ExecContext(ctx, `CREATE FUNCTION reject_console_unenrollment_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic lifecycle audit failure'; END; $$; CREATE TRIGGER reject_console_unenrollment_audit BEFORE INSERT ON mdm_windows_unenrollment_request_audit FOR EACH ROW EXECUTE FUNCTION reject_console_unenrollment_audit()`); err != nil {
				t.Fatal(err)
			}
			if response := request(admin, "POST", path+"/release", review); response.Code != 503 {
				t.Fatal("release audit failure returned an unexpected status", response.Code)
			}
			if response := request(admin, "GET", path, nil); response.Code != 503 || strings.Contains(response.Body.String(), "Retire &lt;script&gt;") {
				t.Fatal("failed read audit exposed protected detail", response.Code)
			}
			if _, err := h.Model.DB.ExecContext(ctx, `DROP TRIGGER reject_console_unenrollment_audit ON mdm_windows_unenrollment_request_audit; DROP FUNCTION reject_console_unenrollment_audit()`); err != nil {
				t.Fatal(err)
			}
			if d := read(device, id); d.Release != nil || d.Command.Revision != result.Command.Revision {
				t.Fatal("audit failure committed partial review")
			}
			if response := request(admin, "POST", path+"/release", review); response.Code != 303 {
				t.Fatal("review submission failed", response.Code)
			}
			d := read(device, id)
			expected := result.Command.Phase
			if expected == "sent" {
				expected = "unknown"
			}
			if d.Release == nil || d.Command.Phase != expected || d.Outcomes[0].Status != result.Outcomes[0].Status {
				t.Fatal("review invented an operation outcome")
			}
			if response := request(admin, "POST", path+"/release", review); response.Code != 409 {
				t.Fatal("stale/repeated review admitted", response.Code)
			}
			page := request(admin, "GET", path, nil)
			if !strings.Contains(page.Body.String(), "Review recorded") || !strings.Contains(page.Body.String(), "&lt;script&gt;missing report&lt;/script&gt;") || strings.Contains(page.Body.String(), `name="confirm_release"`) {
				t.Fatal("review history lost meaning or escaping")
			}
			disconnect()
			page = request(admin, "GET", path, nil)
			if !strings.Contains(page.Body.String(), "Disconnection reported; access revoked") || !strings.Contains(page.Body.String(), "Review recorded") || strings.Contains(page.Body.String(), `name="confirm_release"`) {
				t.Fatal("late report rewrote history or reopened action")
			}
			artifact("windows-disconnection-reviewed-report-"+status, page)
		}
		if fixture := os.Getenv("OPENUEM_WINDOWS_DISCONNECTION_BROWSER_FIXTURE"); fixture != "" {
			device, exchange, _ := windowsConsoleQueuedPeer(t, h, ctx, scope)
			for n := 0; n < 11; n++ {
				cancel(device, create(device, draft()))
			}
			id := create(device, draft())
			exchange(id, "")
			path := base + "/windows/" + device + "/disconnections/" + id
			paths["sent"] = path
			paths["history"] = base + "/windows/" + device + "/disconnections"
			metadata, err := json.Marshal(paths)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(fixture+".paths.json", metadata, 0600); err != nil {
				t.Fatal(err)
			}
			runConsoleBrowserFixture(t, h, ctx, fixture, path)
		}
	})
}
