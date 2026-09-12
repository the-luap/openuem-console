package handlers

import (
	"context"
	"fmt"
	"html"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func exerciseWindowsRingConsole(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	t.Run("Windows ring review, scoped history and concurrent revisions", func(t *testing.T) {
		base := fmt.Sprintf("/tenant/%d/site/%d/windows/update-rings", scope.TenantID, scope.SiteID)
		count := func(table string) int {
			t.Helper()
			var n int
			// Callers below use only these fixed, test-owned table names.
			switch table {
			case "mdm_windows_update_ring_revisions", "mdm_windows_update_runs":
			default:
				t.Fatal("unexpected fixture table")
			}
			if err := h.Model.DB.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		revisions, runs := count("mdm_windows_update_ring_revisions"), count("mdm_windows_update_runs")
		form := windowsRingTestForm()
		for _, suffix := range []string{"", "/new", "/" + form.Get("ring_id"), "/" + form.Get("ring_id") + "/edit", "/preview", "/save"} {
			method := "GET"
			if suffix == "/preview" || suffix == "/save" {
				method = "POST"
			}
			if w := request("scoped-viewer", method, base+suffix, form); w.Code != 403 {
				t.Fatal("viewer reached ring route", suffix, w.Code)
			}
		}
		for _, path := range []string{"/windows/update-rings", fmt.Sprintf("/tenant/%d/windows/update-rings", scope.TenantID)} {
			if w := request("organization-admin", "GET", path, nil); w.Code != 400 {
				t.Fatal("ring list accepted organization-wide scope", w.Code)
			}
		}
		w := request("scoped-operator", "GET", base+"/new", nil)
		if w.Code != 200 || w.Header().Get("Referrer-Policy") != "strict-origin" {
			t.Fatal("ring editor unavailable", w.Code)
		}
		for _, name := range []string{"ring_id", "request_key", "expected_revision"} {
			match := regexp.MustCompile(`name="` + name + `" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
			if len(match) != 2 {
				t.Fatal("missing stable editor identity", name)
			}
			form.Set(name, html.UnescapeString(match[1]))
		}
		artifact("windows-ring-new", w)
		form.Set("name", "Synthetic <script>ring</script>")
		ringID := form.Get("ring_id")
		w = request("scoped-operator", "POST", base+"/preview", form)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Nothing has been saved by this preview") || strings.Contains(w.Body.String(), "<script>ring</script>") || !strings.Contains(w.Body.String(), "<dd>No</dd>") || count("mdm_windows_update_ring_revisions") != revisions {
			t.Fatal("ring preview lost meaning or mutated state", w.Code)
		}
		artifact("windows-ring-preview", w)
		form.Set("edit_ring", "yes")
		if w := request("scoped-operator", "POST", base+"/preview", form); w.Code != 200 || !strings.Contains(w.Body.String(), ringID) || !strings.Contains(w.Body.String(), `name="quality_deferral_days"`) {
			t.Fatal("edit lost ring draft", w.Code)
		}
		form.Del("edit_ring")
		form.Set("quality_deadline_days", "")
		if w := request("scoped-operator", "POST", base+"/preview", form); w.Code != 400 || !strings.Contains(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), ringID) {
			t.Fatal("invalid preview lost draft", w.Code)
		}
		form.Set("quality_deadline_days", "0")
		if w := request("scoped-operator", "POST", base+"/save", form); w.Code != 400 {
			t.Fatal("unconfirmed ring saved", w.Code)
		}
		form.Set("confirm_ring", "yes")
		for name, change := range map[string]func(url.Values){"CSRF": func(f url.Values) { f.Set("csrf", "wrong") }, "scope override": func(f url.Values) { f.Set("tenant", "999") }, "duplicate": func(f url.Values) { f.Add("enabled", "false") }} {
			bad, _ := url.ParseQuery(form.Encode())
			change(bad)
			w := request("scoped-operator", "POST", base+"/save", bad)
			expected := 400
			if name == "CSRF" {
				expected = 403
			}
			if w.Code != expected {
				t.Fatal("ring form boundary failed", name, w.Code)
			}
		}
		if w := request("scoped-operator", "POST", base+"/save?enabled=false", form); w.Code != 400 {
			t.Fatal("ring action accepted query")
		}
		for range 3 {
			if w := request("scoped-operator", "POST", base+"/save", form); w.Code != 303 || w.Header().Get("Location") != base+"/"+ringID || count("mdm_windows_update_ring_revisions") != revisions+1 {
				t.Fatal("ring save was rejected or not idempotent", w.Code)
			}
		}
		saved, err := h.Windows.UpdateRingRevisions(ctx, "scoped-operator", scope, ringID, 0, 1)
		want, parseErr := parseWindowsUpdateRing(form)
		if err != nil || parseErr != nil || len(saved) != 1 || !reflect.DeepEqual(saved[0].Policy, want.Policy) || saved[0].Name != want.Name {
			t.Fatal("saved ring differs from review", err, parseErr)
		}
		// A real site within the same organization must not acquire the ring.
		sibling, err := h.Model.Client.Site.Create().SetDescription("Windows ring sibling").SetTenantID(scope.TenantID).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		foreign := fmt.Sprintf("/tenant/%d/site/%d/windows/update-rings", scope.TenantID, sibling.ID)
		edit := windows_views.UpdateRingFormValues(saved[0], uuid.NewString())
		edit.Set("confirm_ring", "yes")
		for _, suffix := range []string{"/" + ringID, "/" + ringID + "/edit", "/preview", "/save"} {
			method := "GET"
			if suffix == "/preview" || suffix == "/save" {
				method = "POST"
			}
			if w := request("organization-admin", method, foreign+suffix, edit); w.Code != 404 {
				t.Fatal("sibling site accessed ring", suffix, w.Code)
			}
		}
		if w := request("organization-admin", "GET", foreign, nil); w.Code != 200 || strings.Contains(w.Body.String(), ringID) {
			t.Fatal("foreign ring in listing", w.Code)
		}
		w = request("scoped-operator", "GET", base+"/"+ringID+"/edit", nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `name="expected_revision" value="1"`) {
			t.Fatal("editor did not load current revision", w.Code)
		}
		artifact("windows-ring-edit", w)
		firstEdit, _ := url.ParseQuery(edit.Encode())
		edit.Set("enabled", "false")
		edit.Set("feature_deferral_days", "")
		edit.Set("name", "Disabled synthetic ring")
		if w := request("scoped-operator", "POST", base+"/preview", edit); w.Code != 200 || !strings.Contains(w.Body.String(), "Disabled") {
			t.Fatal("disable preview failed", w.Code)
		}
		if w := request("scoped-operator", "POST", base+"/save", edit); w.Code != 303 {
			t.Fatal("disable revision failed", w.Code)
		}
		// A different editor reviewed revision 1 before this save. It cannot overwrite 2.
		firstEdit.Set("request_key", uuid.NewString())
		firstEdit.Set("name", "Retained concurrent draft")
		for _, suffix := range []string{"/preview", "/save"} {
			if w := request("scoped-operator", "POST", base+suffix, firstEdit); w.Code != 409 || !strings.Contains(w.Body.String(), "Retained concurrent draft") || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("concurrent edit silently overwrote or discarded draft", suffix, w.Code)
			}
		}
		if w := request("scoped-operator", "POST", base+"/save", edit); w.Code != 303 || count("mdm_windows_update_ring_revisions") != revisions+2 {
			t.Fatal("edit retry duplicated revision", w.Code)
		}
		if w := request("scoped-operator", "POST", base+"/save", form); w.Code != 303 || count("mdm_windows_update_ring_revisions") != revisions+2 {
			t.Fatal("original retry failed after head changed", w.Code)
		}
		w = request("scoped-operator", "GET", base+"/"+ringID, nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Revision 2") || !strings.Contains(w.Body.String(), "Revision 1") || strings.Contains(w.Body.String(), "<script>ring</script>") {
			t.Fatal("immutable history missing", w.Code)
		}
		artifact("windows-ring-history", w)
		w = request("scoped-operator", "GET", base, nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Disabled synthetic ring") {
			t.Fatal("current listing omitted disabled ring", w.Code)
		}
		artifact("windows-rings", w)
		for _, query := range []string{"before=01", "before=-1", "before=1000002", "before=1&before=2", "before="} {
			if w := request("scoped-operator", "GET", base+"/"+ringID+"?"+query, nil); w.Code != 400 {
				t.Fatal("ambiguous history cursor admitted", query, w.Code)
			}
		}
		// Review never transfers durable authority to a later confirmation.
		actor := "windows-ring-review-operator"
		if _, err := h.Model.Client.User.Create().SetID(actor).SetName(actor).SetEmail(actor + "@example.test").SetUse2fa(false).SetRegister("users.completed").Save(ctx); err != nil {
			t.Fatal(err)
		}
		if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 0, []access.Grant{{Role: access.Operator, Scope: scope}}); err != nil {
			t.Fatal(err)
		}
		fresh := windowsRingTestForm()
		fresh.Set("confirm_ring", "yes")
		if w := request(actor, "POST", base+"/preview", fresh); w.Code != 200 {
			t.Fatal("operator preview failed", w.Code)
		}
		if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 1, []access.Grant{{Role: access.Viewer, Scope: scope}}); err != nil {
			t.Fatal(err)
		}
		if w := request(actor, "POST", base+"/save", fresh); w.Code != 403 {
			t.Fatal("stale ring preview granted write authority", w.Code)
		}
		// Audited reads fail closed; a failed save audit leaves no new ring/revision.
		if _, err := h.Model.DB.ExecContext(ctx, `CREATE FUNCTION fail_windows_ring_console_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic private ring failure'; END $$; CREATE TRIGGER fail_windows_ring_console_audit BEFORE INSERT ON mdm_windows_update_ring_audit FOR EACH ROW EXECUTE FUNCTION fail_windows_ring_console_audit()`); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if _, err := h.Model.DB.ExecContext(ctx, `DROP TRIGGER fail_windows_ring_console_audit ON mdm_windows_update_ring_audit; DROP FUNCTION fail_windows_ring_console_audit()`); err != nil {
					t.Error(err)
				}
			}()
			for _, suffix := range []string{"", "/" + ringID, "/" + ringID + "/edit"} {
				if w := request("scoped-operator", "GET", base+suffix, nil); w.Code != 503 || strings.Contains(w.Body.String(), "synthetic private ring failure") || strings.Contains(w.Body.String(), "Disabled synthetic ring") {
					t.Fatal("failed read audit exposed ring", suffix, w.Code)
				}
			}
			if w := request("scoped-operator", "POST", base+"/save", fresh); w.Code != 503 || strings.Contains(w.Body.String(), "synthetic private ring failure") || count("mdm_windows_update_ring_revisions") != revisions+2 {
				t.Fatal("failed audit committed ring or leaked SQL", w.Code)
			}
			var exists bool
			if err := h.Model.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_windows_update_rings WHERE id=$1)`, fresh.Get("ring_id")).Scan(&exists); err != nil || exists {
				t.Fatal("failed save left ring head", err)
			}
		}()
		current, err := h.Windows.UpdateRingRevisions(ctx, "scoped-operator", scope, ringID, 0, 1)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 25; i++ {
			next, err := h.Windows.SaveUpdateRing(ctx, "scoped-operator", scope, ringID, uuid.NewString(), current[0].Revision, "Paged ring", current[0].Policy, false)
			if err != nil {
				t.Fatal(err)
			}
			current[0] = *next
		}
		w = request("scoped-operator", "GET", base+"/"+ringID, nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "?before=3") || strings.Contains(w.Body.String(), `id="revision-2"`) {
			t.Fatal("history page did not preserve bounded revision cursor", w.Code)
		}
		w = request("scoped-operator", "GET", base+"/"+ringID+"?before=3", nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `id="revision-2"`) || !strings.Contains(w.Body.String(), `id="revision-1"`) || strings.Contains(w.Body.String(), "Current revision") {
			t.Fatal("older page lost history or mislabeled head", w.Code)
		}
		for range 25 {
			if _, err := h.Windows.SaveUpdateRing(ctx, "scoped-operator", scope, uuid.NewString(), uuid.NewString(), 0, "Listed ring", want.Policy, true); err != nil {
				t.Fatal(err)
			}
		}
		if w := request("scoped-operator", "GET", base, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "?offset=25") {
			t.Fatal("missing next ring page", w.Code)
		}
		if w := request("scoped-operator", "GET", base+"?offset=25", nil); w.Code != 200 || !strings.Contains(w.Body.String(), ringID) || strings.Contains(w.Body.String(), "More rings") {
			t.Fatal("ring pagination lost oldest ring", w.Code)
		}
		if count("mdm_windows_update_runs") != runs {
			t.Fatal("saving a ring admitted device work")
		}
	})
}
