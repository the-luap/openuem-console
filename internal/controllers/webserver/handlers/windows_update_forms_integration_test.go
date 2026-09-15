package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func exerciseWindowsUpdatePolicyForms(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, deviceID string, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	t.Run("Windows policy preview and confirmed immutable queue admission", func(t *testing.T) {
		base := fmt.Sprintf("/tenant/%d/site/%d/windows/%s/updates", scope.TenantID, scope.SiteID, deviceID)
		for _, path := range []string{base + "/new", base + "/preview", base + "/create"} {
			method := "POST"
			if strings.HasSuffix(path, "/new") {
				method = "GET"
			}
			if w := request("scoped-viewer", method, path, windowsPolicyTestForm()); w.Code != 403 {
				t.Fatal("reader reached policy mutation form", w.Code)
			}
		}
		w := request("scoped-operator", "GET", base+"/new", nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Review policy and device") || w.Header().Get("Referrer-Policy") != "strict-origin" {
			t.Fatal("policy creation form unavailable", w.Code)
		}
		artifact("windows-policy-form", w)
		key := regexp.MustCompile(`name="request_key" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
		if len(key) != 2 {
			t.Fatal("new form did not create a stable request key")
		}
		form := windowsPolicyTestForm()
		form.Set("request_key", key[1])
		form.Set("name", "Synthetic <script>policy review</script>")
		sibling, err := h.Model.Client.Site.Create().SetDescription("Windows policy form sibling").SetTenantID(scope.TenantID).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		foreign := fmt.Sprintf("/tenant/%d/site/%d/windows/%s/updates", scope.TenantID, sibling.ID, deviceID)
		for _, suffix := range []string{"/new", "/preview", "/create"} {
			method := "POST"
			if suffix == "/new" {
				method = "GET"
			}
			if w := request("organization-admin", method, foreign+suffix, form); w.Code != 404 {
				t.Fatal("sibling site acquired policy form authority", w.Code)
			}
		}
		countRuns := func() int {
			t.Helper()
			var count int
			if err := h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_windows_update_runs WHERE device_id=$1`, deviceID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			return count
		}
		before := countRuns()
		w = request("scoped-operator", "POST", base+"/preview", form)
		if w.Code != 200 || countRuns() != before || !strings.Contains(w.Body.String(), "Nothing has been queued by this preview") || !strings.Contains(w.Body.String(), key[1]) || strings.Contains(w.Body.String(), "<script>policy review</script>") {
			t.Fatal("preview changed state or lost reviewed intent", w.Code)
		}
		artifact("windows-policy-preview", w)
		form.Set("edit_policy", "yes")
		w = request("scoped-operator", "POST", base+"/preview", form)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Configure Windows update policy") || !strings.Contains(w.Body.String(), key[1]) || countRuns() != before {
			t.Fatal("edit from preview lost the draft")
		}
		form.Del("edit_policy")
		form.Set("quality_deadline_days", "")
		w = request("scoped-operator", "POST", base+"/preview", form)
		if w.Code != 400 || !strings.Contains(w.Header().Get("Content-Type"), "text/html") || w.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(w.Body.String(), "need their matching deadline") || !strings.Contains(w.Body.String(), key[1]) || countRuns() != before {
			t.Fatal("invalid dependent settings lost draft or queued work", w.Code)
		}
		form.Set("quality_deadline_days", "0")
		if w := request("scoped-operator", "POST", base+"/create", form); w.Code != 400 || countRuns() != before {
			t.Fatal("policy queued without explicit confirmation")
		}
		form.Set("confirm_policy", "yes")
		form.Set("csrf", "wrong")
		if w := request("scoped-operator", "POST", base+"/create", form); w.Code != 403 || countRuns() != before {
			t.Fatal("policy queued with invalid CSRF")
		}
		form.Set("csrf", "console-test-token")
		form.Set("tenant", "999")
		if w := request("scoped-operator", "POST", base+"/create", form); w.Code != 400 {
			t.Fatal("scope override form field admitted")
		}
		form.Del("tenant")
		form.Add("exclude_drivers", "true")
		if w := request("scoped-operator", "POST", base+"/create", form); w.Code != 400 {
			t.Fatal("repeated policy setting admitted")
		}
		form.Set("exclude_drivers", "false")
		if w := request("scoped-operator", "POST", base+"/create?mode=remove", form); w.Code != 400 {
			t.Fatal("policy action accepted query data")
		}
		w = request("scoped-operator", "POST", base+"/create", form)
		location := w.Header().Get("Location")
		if w.Code != 303 || !strings.HasPrefix(location, base+"/") || countRuns() != before+1 {
			t.Fatal("confirmed full policy was not queued once", w.Code)
		}
		runID := strings.TrimPrefix(location, base+"/")
		wantPolicy, _, err := parseWindowsUpdatePolicy(form)
		if err != nil {
			t.Fatal(err)
		}
		detail, err := h.Windows.UpdateRunDetails(ctx, "scoped-operator", scope, deviceID, runID)
		if err != nil || !reflect.DeepEqual(detail.Policy, wantPolicy) || detail.Phase != "preflight_pending" || len(detail.Steps) != 7 || detail.Run.Mode != "apply" {
			t.Fatal("queued intent differs from the full reviewed policy", err)
		}
		for range 3 {
			if w := request("scoped-operator", "POST", base+"/create", form); w.Code != 303 || w.Header().Get("Location") != location || countRuns() != before+1 {
				t.Fatal("repeated browser submission duplicated policy work", w.Code)
			}
		}
		form.Set("quality_deferral_days", "1")
		if w := request("scoped-operator", "POST", base+"/create", form); w.Code != 409 || countRuns() != before+1 {
			t.Fatal("request key silently changed its policy")
		}
		form.Set("quality_deferral_days", "0")
		form.Set("request_key", uuid.NewString())
		form.Set("mode", "remove")
		w = request("scoped-operator", "POST", base+"/preview", form)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "will not be applied by a removal run") || countRuns() != before+1 {
			t.Fatal("removal preview changed state or hid action", w.Code)
		}
		artifact("windows-policy-removal-preview", w)
		w = request("scoped-operator", "POST", base+"/create", form)
		if w.Code != 303 || countRuns() != before+2 {
			t.Fatal("confirmed removal form rejected", w.Code)
		}
		removedID := strings.TrimPrefix(w.Header().Get("Location"), base+"/")
		if d, err := h.Windows.UpdateRunDetails(ctx, "scoped-operator", scope, deviceID, removedID); err != nil || d.Run.Mode != "remove" || !reflect.DeepEqual(d.Policy, wantPolicy) {
			t.Fatal("removal form changed typed selection", err)
		}

		// The review confers no enduring authority. Test a separate actor so
		// existing enrollment and update fixtures retain their creator revisions.
		actor := "windows-review-operator"
		if _, err := h.Model.Client.User.Create().SetID(actor).SetName(actor).SetEmail(actor + "@example.test").SetUse2fa(false).SetRegister("users.completed").Save(ctx); err != nil {
			t.Fatal(err)
		}
		if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 0, []access.Grant{{Role: access.Operator, Scope: scope}}); err != nil {
			t.Fatal(err)
		}
		form.Set("request_key", uuid.NewString())
		if w := request(actor, "POST", base+"/preview", form); w.Code != 200 {
			t.Fatal("live operator preview failed", w.Code)
		}
		if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 1, []access.Grant{{Role: access.Viewer, Scope: scope}}); err != nil {
			t.Fatal(err)
		}
		if w := request(actor, "POST", base+"/create", form); w.Code != 403 || countRuns() != before+2 {
			t.Fatal("stale preview conferred queue authority", w.Code)
		}

		if _, err := h.Model.DB.ExecContext(ctx, `CREATE FUNCTION fail_windows_policy_form_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic private policy error'; END $$; CREATE TRIGGER fail_windows_policy_form_audit BEFORE INSERT ON mdm_windows_update_audit FOR EACH ROW EXECUTE FUNCTION fail_windows_policy_form_audit()`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := h.Model.DB.ExecContext(ctx, `DROP TRIGGER fail_windows_policy_form_audit ON mdm_windows_update_audit; DROP FUNCTION fail_windows_policy_form_audit()`); err != nil {
				t.Error(err)
			}
		}()
		if w := request("scoped-operator", "POST", base+"/create", form); w.Code != 503 || countRuns() != before+2 || strings.Contains(w.Body.String(), "private policy error") {
			t.Fatal("audit failure leaked or committed policy intent", w.Code)
		}
	})
}
