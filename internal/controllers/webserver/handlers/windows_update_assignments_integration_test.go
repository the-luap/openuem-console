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

func windowsAssignmentSecondDevice(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, original string, names ...string) string {
	t.Helper()
	invitation, _, err := h.Windows.CreateEnrollmentInvitation(ctx, "apple-console-admin", scope, "cohort-second@example.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id, certID := uuid.NewString(), uuid.NewString()
	name := "Synthetic second Windows"
	if len(names) > 0 {
		name = names[0]
	}
	// These database-only identities never authenticate a transport or install
	// certificates. Each row belongs to the already reserved disposable schema.
	if _, err := h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_windows_devices(id,tenant_id,site_id,invitation_id,reported_device_id,device_name,enrollment_type,os_edition,os_version,application_version) VALUES($1,$2,$3,$4,'SYNTHETIC-SECOND',$5,'Device',4,'10.0.26100.1','10.0.26100.1')`, id, scope.TenantID, scope.SiteID, invitation.ID, name); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_windows_device_certificates(id,device_id,tenant_id,site_id,authority_id,certificate,fingerprint,public_key_fingerprint,serial,issued_at,expires_at) SELECT $1::uuid,$2::uuid,tenant_id,site_id,authority_id,'synthetic second certificate',sha256($2::uuid::text::bytea),sha256($1::uuid::text::bytea),uuid_send($1::uuid),clock_timestamp(),clock_timestamp()+INTERVAL '1 day' FROM mdm_windows_device_certificates WHERE device_id=$3`, certID, id, original); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_windows_enrollments(invitation_id,tenant_id,site_id,device_id,certificate_id,request_digest,configuration_digest,encrypted_provisioning,encrypted_auth) VALUES($1,$2,$3,$4,$5,decode(repeat('05',32),'hex'),decode(repeat('06',32),'hex'),decode(repeat('07',30),'hex'),decode(repeat('08',30),'hex'))`, invitation.ID, scope.TenantID, scope.SiteID, id, certID); err != nil {
		t.Fatal(err)
	}
	return id
}

func exerciseWindowsAssignmentConsole(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, deviceID string, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	t.Run("Windows explicit ring cohorts preserve review and atomic admission", func(t *testing.T) {
		second := windowsAssignmentSecondDevice(t, h, ctx, scope, deviceID)
		zero, disabled := 0, false
		policy := windows.UpdatePolicy{QualityDeferralDays: &zero, ExcludeDrivers: &disabled}
		ring, err := h.Windows.SaveUpdateRing(ctx, "scoped-operator", scope, uuid.NewString(), uuid.NewString(), 0, "Synthetic <script>cohort ring</script>", policy, true)
		if err != nil {
			t.Fatal(err)
		}
		prefix := fmt.Sprintf("/tenant/%d/site/%d/windows", scope.TenantID, scope.SiteID)
		base := prefix + "/update-rings/" + ring.RingID + "/assign"
		form := windowsAssignmentTestForm(second, deviceID)
		for _, path := range []string{base + "?revision=1", base + "/preview", base + "/create", prefix + "/update-rollouts/" + uuid.NewString()} {
			method := "GET"
			if strings.HasSuffix(path, "/preview") || strings.HasSuffix(path, "/create") {
				method = "POST"
			}
			if w := request("scoped-viewer", method, path, form); w.Code != 403 {
				t.Fatal("viewer reached protected assignment", path, w.Code)
			}
		}
		w := request("scoped-operator", "GET", base+"?revision=1", nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), "<script>cohort ring</script>") || !strings.Contains(w.Body.String(), "one per line") {
			t.Fatal("assignment form unavailable", w.Code)
		}
		artifact("windows-assignment-form", w)
		for _, query := range []string{"", "?revision=0", "?revision=1&revision=2", "?revision=1&mode=bad", "?revision=1&mode=apply&mode=remove"} {
			if w := request("scoped-operator", "GET", base+query, nil); w.Code != 400 {
				t.Fatal("ambiguous assignment source admitted", query, w.Code)
			}
		}
		counts := func() [3]int {
			t.Helper()
			var n [3]int
			for i, table := range []string{"mdm_windows_update_rollouts", "mdm_windows_update_runs", "mdm_windows_csp_commands"} {
				if err := h.Model.DB.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n[i]); err != nil {
					t.Fatal(err)
				}
			}
			return n
		}
		before := counts()
		w = request("scoped-operator", "POST", base+"/preview", form)
		if w.Code != 200 || counts() != before || !strings.Contains(w.Body.String(), deviceID) || !strings.Contains(w.Body.String(), second) || strings.Contains(w.Body.String(), "<script>Windows</script>") || !strings.Contains(w.Body.String(), "<dd>No</dd>") {
			t.Fatal("preview changed state, escaped names or device set", w.Code)
		}
		artifact("windows-assignment-preview", w)
		form.Set("edit_assignment", "yes")
		if w := request("scoped-operator", "POST", base+"/preview", form); w.Code != 200 || !strings.Contains(w.Body.String(), second) || counts() != before {
			t.Fatal("edit lost selected devices", w.Code)
		}
		form.Del("edit_assignment")
		bad, _ := url.ParseQuery(form.Encode())
		bad.Set("devices", second+"\n"+second)
		if w := request("scoped-operator", "POST", base+"/preview", bad); w.Code != 400 || !strings.Contains(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), second) || !strings.Contains(w.Body.String(), "only once") {
			t.Fatal("invalid target draft was lost", w.Code)
		}
		if w := request("scoped-operator", "POST", base+"/create", form); w.Code != 400 || counts() != before {
			t.Fatal("unconfirmed cohort admitted", w.Code)
		}
		form.Set("confirm_assignment", "yes")
		for name, change := range map[string]func(url.Values){"csrf": func(f url.Values) { f.Set("csrf", "wrong") }, "repeat": func(f url.Values) { f.Add("devices", deviceID) }, "scope": func(f url.Values) { f.Set("tenant", "999") }} {
			bad, _ := url.ParseQuery(form.Encode())
			change(bad)
			want := 400
			if name == "csrf" {
				want = 403
			}
			if w := request("scoped-operator", "POST", base+"/create", bad); w.Code != want || counts() != before {
				t.Fatal("assignment form boundary failed", name, w.Code)
			}
		}
		if w := request("scoped-operator", "POST", base+"/create?mode=remove", form); w.Code != 400 {
			t.Fatal("query changed assignment")
		}
		// The missing UUID sorts after enrolled targets, so failure must roll back
		// earlier device runs and all their queued commands in the same transaction.
		bad, _ = url.ParseQuery(form.Encode())
		bad.Set("devices", deviceID+"\nffffffff-ffff-4fff-8fff-ffffffffffff")
		if w := request("scoped-operator", "POST", base+"/create", bad); w.Code != 404 || counts() != before {
			t.Fatal("missing late target partially admitted cohort", w.Code)
		}
		w = request("scoped-operator", "POST", base+"/create", form)
		location := w.Header().Get("Location")
		if w.Code != 303 || !strings.HasPrefix(location, prefix+"/update-rollouts/") {
			t.Fatal("confirmed cohort rejected", w.Code)
		}
		rolloutID := strings.TrimPrefix(location, prefix+"/update-rollouts/")
		rollout, err := h.Windows.UpdateRolloutDetails(ctx, "scoped-operator", scope, rolloutID)
		if err != nil || len(rollout.Runs) != 2 || rollout.RingRevision != 1 || rollout.Mode != "apply" {
			t.Fatal("admitted cohort differs from review", err)
		}
		after := counts()
		if after[0] != before[0]+1 || after[1] != before[1]+2 || after[2] != before[2]+6 {
			t.Fatal("cohort did not admit exactly two three-step runs")
		}
		form.Set("devices", deviceID+"\r\n"+second)
		for range 3 {
			if w := request("scoped-operator", "POST", base+"/create", form); w.Code != 303 || w.Header().Get("Location") != location || counts() != after {
				t.Fatal("cohort retry duplicated work", w.Code)
			}
		}
		w = request("scoped-operator", "GET", location, nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Waiting for platform evidence") || !strings.Contains(w.Body.String(), second) || !strings.Contains(w.Body.String(), rollout.Runs[0].ID) || strings.Contains(w.Body.String(), "<script>cohort ring</script>") {
			t.Fatal("rollout history unavailable or unsafe", w.Code)
		}
		artifact("windows-assignment-history", w)
		sibling, err := h.Model.Client.Site.Create().SetDescription("Windows cohort sibling").SetTenantID(scope.TenantID).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		foreign := fmt.Sprintf("/tenant/%d/site/%d/windows", scope.TenantID, sibling.ID)
		for _, path := range []string{strings.Replace(base, prefix, foreign, 1) + "?revision=1", strings.Replace(base, prefix, foreign, 1) + "/preview", strings.Replace(base, prefix, foreign, 1) + "/create", foreign + "/update-rollouts/" + rolloutID} {
			method := "GET"
			if strings.HasSuffix(path, "/preview") || strings.HasSuffix(path, "/create") {
				method = "POST"
			}
			if w := request("organization-admin", method, path, form); w.Code != 404 {
				t.Fatal("sibling site accessed assignment", w.Code)
			}
		}
		// An apply preview is no guarantee that its ring stays current until submit.
		changed, _ := url.ParseQuery(form.Encode())
		changed.Set("request_key", uuid.NewString())
		if w := request("scoped-operator", "POST", base+"/preview", changed); w.Code != 200 {
			t.Fatal("eligible apply preview failed", w.Code)
		}
		if _, err := h.Windows.SaveUpdateRing(ctx, "scoped-operator", scope, ring.RingID, uuid.NewString(), 1, "Disabled later revision", policy, false); err != nil {
			t.Fatal(err)
		}
		for _, suffix := range []string{"/preview", "/create"} {
			if w := request("scoped-operator", "POST", base+suffix, changed); w.Code != 409 || counts() != after {
				t.Fatal("stale apply revision admitted", suffix, w.Code)
			}
		}
		if w := request("scoped-operator", "POST", base+"/create", form); w.Code != 303 || w.Header().Get("Location") != location || counts() != after {
			t.Fatal("exact prior assignment retry lost immutable source", w.Code)
		}
		bad, _ = url.ParseQuery(form.Encode())
		bad.Set("devices", deviceID)
		if w := request("scoped-operator", "POST", base+"/create", bad); w.Code != 409 || counts() != after {
			t.Fatal("committed request changed target set", w.Code)
		}
		changed.Set("mode", "remove")
		w = request("scoped-operator", "POST", base+"/preview", changed)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "historical revision") || !strings.Contains(w.Body.String(), "will not be applied") {
			t.Fatal("historical removal not reviewed explicitly", w.Code)
		}
		artifact("windows-assignment-removal-preview", w)
		w = request("scoped-operator", "POST", base+"/create", changed)
		if w.Code != 303 {
			t.Fatal("historical removal rejected", w.Code)
		}
		removal, err := h.Windows.UpdateRolloutDetails(ctx, "scoped-operator", scope, strings.TrimPrefix(w.Header().Get("Location"), prefix+"/update-rollouts/"))
		if err != nil || removal.Mode != "remove" || removal.RingRevision != 1 || len(removal.Runs) != 2 {
			t.Fatal("removal lost original source", err)
		}
		after = counts()
		actor := "windows-cohort-review-operator"
		if _, err := h.Model.Client.User.Create().SetID(actor).SetName(actor).SetEmail(actor + "@example.test").SetUse2fa(false).SetRegister("users.completed").Save(ctx); err != nil {
			t.Fatal(err)
		}
		if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 0, []access.Grant{{Role: access.Operator, Scope: scope}}); err != nil {
			t.Fatal(err)
		}
		changed.Set("request_key", uuid.NewString())
		if w := request(actor, "POST", base+"/preview", changed); w.Code != 200 {
			t.Fatal("new actor removal review failed", w.Code)
		}
		if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 1, []access.Grant{{Role: access.Viewer, Scope: scope}}); err != nil {
			t.Fatal(err)
		}
		if w := request(actor, "POST", base+"/create", changed); w.Code != 403 || counts() != after {
			t.Fatal("stale preview carried durable authority", w.Code)
		}
		runConsoleBrowserFixture(t, h, ctx, os.Getenv("OPENUEM_WINDOWS_ASSIGNMENT_BROWSER_FIXTURE"), base+"?revision=1&mode=remove")
		after = counts()
		if _, err := h.Model.DB.ExecContext(ctx, `CREATE FUNCTION fail_windows_assignment_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private cohort audit failure'; END $$; CREATE TRIGGER fail_windows_assignment_audit BEFORE INSERT ON mdm_windows_update_ring_audit FOR EACH ROW EXECUTE FUNCTION fail_windows_assignment_audit()`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := h.Model.DB.ExecContext(ctx, `DROP TRIGGER fail_windows_assignment_audit ON mdm_windows_update_ring_audit; DROP FUNCTION fail_windows_assignment_audit()`); err != nil {
				t.Error(err)
			}
		}()
		if w := request("scoped-operator", "POST", base+"/create", changed); w.Code != 503 || strings.Contains(w.Body.String(), "private cohort audit failure") || counts() != after {
			t.Fatal("late audit failure committed partial cohort", w.Code)
		}
		if w := request("scoped-operator", "GET", location, nil); w.Code != 503 || strings.Contains(w.Body.String(), "private cohort audit failure") || strings.Contains(w.Body.String(), second) {
			t.Fatal("unaudited rollout read escaped", w.Code)
		}
	})
}
