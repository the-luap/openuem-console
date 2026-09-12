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

func exerciseWindowsScheduleConsole(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, deviceID string, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	t.Run("Windows reviewed schedules preserve timing, authority and lifecycle", func(t *testing.T) {
		devices, err := h.Windows.Devices(ctx, "scoped-operator", scope, "", 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		second := ""
		for _, device := range devices {
			if device.ID != deviceID {
				second = device.ID
				break
			}
		}
		if second == "" {
			t.Fatal("schedule fixture needs the second synthetic cohort device")
		}
		zero := 0
		policy := windows.UpdatePolicy{QualityDeferralDays: &zero}
		ring, err := h.Windows.SaveUpdateRing(ctx, "scoped-operator", scope, uuid.NewString(), uuid.NewString(), 0, "Schedule <script>source</script>", policy, true)
		if err != nil {
			t.Fatal(err)
		}
		prefix := fmt.Sprintf("/tenant/%d/site/%d/windows", scope.TenantID, scope.SiteID)
		base := prefix + "/update-rings/" + ring.RingID + "/schedule"
		list := prefix + "/update-schedules"
		start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Minute)
		form := windowsAssignmentTestForm(deviceID, second)
		form.Set("not_before", start.Format(windowsScheduleTimeLayout))
		form.Set("activation_minutes", "90")
		for _, path := range []string{base + "?revision=1", base + "/preview", base + "/create", list, list + "/" + uuid.NewString(), list + "/" + uuid.NewString() + "/cancel"} {
			method := "GET"
			if strings.HasSuffix(path, "/preview") || strings.HasSuffix(path, "/create") || strings.HasSuffix(path, "/cancel") {
				method = "POST"
			}
			if w := request("scoped-viewer", method, path, form); w.Code != 403 {
				t.Fatal("viewer accessed schedule route", path, w.Code)
			}
		}
		w := request("scoped-operator", "GET", base+"?revision=1", nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Schedule Windows update ring") || !strings.Contains(w.Body.String(), "Activate no earlier than (UTC)") || !strings.Contains(w.Body.String(), "Review schedule and devices") {
			t.Fatal("schedule editor unavailable", w.Code)
		}
		artifact("windows-schedule-form", w)
		counts := func() [3]int {
			t.Helper()
			var n [3]int
			for i, table := range []string{"mdm_windows_update_schedules", "mdm_windows_update_runs", "mdm_windows_csp_commands"} {
				if err := h.Model.DB.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n[i]); err != nil {
					t.Fatal(err)
				}
			}
			return n
		}
		before := counts()
		w = request("scoped-operator", "POST", base+"/preview", form)
		if w.Code != 200 || counts() != before || !strings.Contains(w.Body.String(), start.Format("2006-01-02 15:04:05 UTC")) || !strings.Contains(w.Body.String(), start.Add(90*time.Minute).Format("2006-01-02 15:04:05 UTC")) || !strings.Contains(w.Body.String(), second) || !strings.Contains(w.Body.String(), "Current certificate expires before activation.") || strings.Contains(w.Body.String(), "<script>source</script>") || strings.Contains(w.Body.String(), `name="confirm_assignment"`) {
			t.Fatal("schedule preview changed timing, intent or state", w.Code)
		}
		artifact("windows-schedule-preview", w)
		form.Set("edit_assignment", "yes")
		if w := request("scoped-operator", "POST", base+"/preview", form); w.Code != 200 || !strings.Contains(w.Body.String(), form.Get("not_before")) || !strings.Contains(w.Body.String(), second) || counts() != before {
			t.Fatal("schedule edit lost original draft", w.Code)
		}
		form.Del("edit_assignment")
		for name, change := range map[string]func(url.Values){"invalid time": func(f url.Values) { f.Set("not_before", start.Format(time.RFC3339)) }, "past": func(f url.Values) { f.Set("not_before", "2020-01-01T00:00") }, "too far": func(f url.Values) {
			f.Set("not_before", time.Now().UTC().Add(92*24*time.Hour).Format(windowsScheduleTimeLayout))
		}, "window": func(f url.Values) { f.Set("activation_minutes", "0") }, "duplicate device": func(f url.Values) { f.Set("devices", deviceID+"\n"+deviceID) }} {
			bad, _ := url.ParseQuery(form.Encode())
			change(bad)
			w := request("scoped-operator", "POST", base+"/preview", bad)
			if w.Code != 400 || !strings.Contains(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), deviceID) || counts() != before {
				t.Fatal("invalid schedule draft was lost or saved", name, w.Code)
			}
		}
		if w := request("scoped-operator", "POST", base+"/create", form); w.Code != 400 || counts() != before {
			t.Fatal("unconfirmed schedule admitted", w.Code)
		}
		form.Set("confirm_schedule", "yes")
		for name, change := range map[string]func(url.Values){"csrf": func(f url.Values) { f.Set("csrf", "wrong") }, "repeat time": func(f url.Values) { f.Add("not_before", f.Get("not_before")) }, "scope override": func(f url.Values) { f.Set("site", "999") }, "wrong confirmation": func(f url.Values) { f.Set("confirm_assignment", "yes") }} {
			bad, _ := url.ParseQuery(form.Encode())
			change(bad)
			want := 400
			if name == "csrf" {
				want = 403
			}
			if w := request("scoped-operator", "POST", base+"/create", bad); w.Code != want || counts() != before {
				t.Fatal("schedule form boundary failed", name, w.Code)
			}
		}
		if w := request("scoped-operator", "POST", base+"/create?activation_minutes=1", form); w.Code != 400 {
			t.Fatal("schedule action accepted query values")
		}
		// Admission checks new-work time again; parser acceptance does not admit an
		// expired new request. Already committed exact replay takes the store's path.
		past, _ := url.ParseQuery(form.Encode())
		past.Set("not_before", "2020-01-01T00:00")
		if w := request("scoped-operator", "POST", base+"/create", past); w.Code != 400 || counts() != before {
			t.Fatal("past new plan admitted", w.Code)
		}
		w = request("scoped-operator", "POST", base+"/create", form)
		location := w.Header().Get("Location")
		if w.Code != 303 || !strings.HasPrefix(location, list+"/") {
			t.Fatal("confirmed schedule rejected", w.Code)
		}
		id := strings.TrimPrefix(location, list+"/")
		stored, err := h.Windows.UpdateScheduleDetails(ctx, "scoped-operator", scope, id)
		if err != nil || !stored.NotBefore.Equal(start) || stored.ExpiresAt.Sub(start) != 90*time.Minute || stored.Lifetime != 24*time.Hour || len(stored.Targets) != 2 || stored.Phase != "scheduled" || stored.Revision != 1 {
			t.Fatal("stored schedule differs from review", err)
		}
		after := counts()
		if after[0] != before[0]+1 || after[1] != before[1] || after[2] != before[2] {
			t.Fatal("saving a schedule created device work")
		}
		if progress, err := h.Windows.ProcessDueUpdateSchedules(ctx, 25); err != nil || progress.Activated != 0 || counts() != after {
			t.Fatal("future plan activated early", err)
		}
		for range 3 {
			if w := request("scoped-operator", "POST", base+"/create", form); w.Code != 303 || w.Header().Get("Location") != location || counts() != after {
				t.Fatal("schedule replay duplicated intent", w.Code)
			}
		}
		for _, path := range []string{list, location} {
			w := request("scoped-operator", "GET", path, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), id) || !strings.Contains(w.Body.String(), "Scheduled; not activated") || strings.Contains(w.Body.String(), "<script>source</script>") {
				t.Fatal("protected schedule history unavailable", path, w.Code)
			}
		}
		artifact("windows-schedules", request("scoped-operator", "GET", list, nil))
		artifact("windows-schedule-pending", request("scoped-operator", "GET", location, nil))
		sibling, err := h.Model.Client.Site.Create().SetDescription("Windows schedule sibling").SetTenantID(scope.TenantID).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		foreign := fmt.Sprintf("/tenant/%d/site/%d/windows", scope.TenantID, sibling.ID)
		for _, path := range []string{strings.Replace(base, prefix, foreign, 1) + "?revision=1", strings.Replace(base, prefix, foreign, 1) + "/preview", strings.Replace(base, prefix, foreign, 1) + "/create", strings.Replace(location, prefix, foreign, 1), strings.Replace(location, prefix, foreign, 1) + "/cancel"} {
			method := "GET"
			f := form
			if strings.HasSuffix(path, "/preview") || strings.HasSuffix(path, "/create") {
				method = "POST"
			}
			if strings.HasSuffix(path, "/cancel") {
				method = "POST"
				f = url.Values{"expected_revision": {"1"}, "confirm_cancel": {"yes"}}
			}
			if w := request("organization-admin", method, path, f); w.Code != 404 {
				t.Fatal("foreign site accessed schedule", path, w.Code)
			}
		}
		if w := request("organization-admin", "GET", foreign+"/update-schedules", nil); w.Code != 200 || strings.Contains(w.Body.String(), id) {
			t.Fatal("foreign list exposed schedule", w.Code)
		}
		for _, query := range []string{"?offset=-1", "?offset=01", "?offset=1&offset=2", "?offset=100001"} {
			if w := request("scoped-operator", "GET", list+query, nil); w.Code != 400 {
				t.Fatal("ambiguous schedule page admitted", query, w.Code)
			}
		}
		changed, _ := url.ParseQuery(form.Encode())
		changed.Set("activation_minutes", "91")
		if w := request("scoped-operator", "POST", base+"/create", changed); w.Code != 409 || counts() != after {
			t.Fatal("committed schedule changed its window", w.Code)
		}
		changed.Set("activation_minutes", "90")
		changed.Set("request_key", uuid.NewString())
		if w := request("scoped-operator", "POST", base+"/preview", changed); w.Code != 200 {
			t.Fatal("eligible schedule preview failed", w.Code)
		}
		if _, err := h.Windows.SaveUpdateRing(ctx, "scoped-operator", scope, ring.RingID, uuid.NewString(), 1, "Disabled later schedule source", policy, false); err != nil {
			t.Fatal(err)
		}
		if w := request("scoped-operator", "POST", base+"/create", changed); w.Code != 409 || counts() != after {
			t.Fatal("source changed between review and save", w.Code)
		}
		if w := request("scoped-operator", "POST", base+"/create", form); w.Code != 303 || w.Header().Get("Location") != location || counts() != after {
			t.Fatal("exact schedule retry lost its historical source", w.Code)
		}
		// Source removal remains an explicit, separately reviewed historical action.
		changed.Set("mode", "remove")
		if w := request("scoped-operator", "POST", base+"/preview", changed); w.Code != 200 || !strings.Contains(w.Body.String(), "historical revision") {
			t.Fatal("historical removal schedule unavailable", w.Code)
		}
		w = request("scoped-operator", "POST", base+"/create", changed)
		if w.Code != 303 {
			t.Fatal("historical removal schedule rejected", w.Code)
		}
		removalLocation := w.Header().Get("Location")
		cancel := url.Values{"expected_revision": {"1"}, "confirm_cancel": {"yes"}}
		if w := request("scoped-operator", "POST", location+"/cancel", url.Values{"expected_revision": {"1"}}); w.Code != 400 {
			t.Fatal("unconfirmed schedule cancellation admitted")
		}
		badCancel := url.Values{"expected_revision": {"1"}, "confirm_cancel": {"yes"}, "csrf": {"wrong"}}
		if w := request("scoped-operator", "POST", location+"/cancel", badCancel); w.Code != 403 {
			t.Fatal("invalid CSRF canceled schedule")
		}
		if w := request("scoped-operator", "POST", location+"/cancel", cancel); w.Code != 303 {
			t.Fatal("pending schedule cancellation failed", w.Code)
		}
		canceled, err := h.Windows.UpdateScheduleDetails(ctx, "scoped-operator", scope, id)
		if err != nil || canceled.Phase != "canceled" || canceled.Revision != 2 {
			t.Fatal("cancellation did not preserve state history", err)
		}
		w = request("scoped-operator", "GET", location, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), `name="confirm_cancel"`) || !strings.Contains(w.Body.String(), "Canceled before activation") {
			t.Fatal("canceled plan kept an active form", w.Code)
		}
		artifact("windows-schedule-canceled", w)
		if w := request("scoped-operator", "POST", location+"/cancel", cancel); w.Code != 409 {
			t.Fatal("stale state revision canceled again", w.Code)
		}
		if w := request("scoped-operator", "POST", base+"/create", form); w.Code != 303 || w.Header().Get("Location") != location {
			t.Fatal("exact retry rearmed canceled schedule", w.Code)
		}
		// A due backend-created plan uses sub-minute precision to avoid tests waiting
		// for a minute boundary. Its actual activation is then read by production UI.
		due, err := h.Windows.ScheduleUpdateRing(ctx, "scoped-operator", scope, ring.RingID, 1, uuid.NewString(), []string{deviceID, second}, true, time.Now().UTC().Truncate(time.Microsecond), time.Hour, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if progress, err := h.Windows.ProcessDueUpdateSchedules(ctx, 25); err != nil || progress.Activated != 1 {
			t.Fatal("due synthetic plan failed to activate", err)
		}
		activated, err := h.Windows.UpdateScheduleDetails(ctx, "scoped-operator", scope, due.ID)
		if err != nil || activated.RolloutID == "" || activated.Phase != "activated" {
			t.Fatal("activation lost rollout", err)
		}
		dueLocation := list + "/" + due.ID
		w = request("scoped-operator", "GET", dueLocation, nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), activated.RolloutID) || strings.Contains(w.Body.String(), `name="confirm_cancel"`) {
			t.Fatal("activated schedule lost linkage or offered cancellation", w.Code)
		}
		artifact("windows-schedule-activated", w)
		for _, revision := range []string{"1", fmt.Sprint(activated.Revision)} {
			if w := request("scoped-operator", "POST", dueLocation+"/cancel", url.Values{"expected_revision": {revision}, "confirm_cancel": {"yes"}}); w.Code != 409 {
				t.Fatal("activation race falsely canceled created work", w.Code)
			}
		}
		if w := request("scoped-operator", "GET", prefix+"/update-rollouts/"+activated.RolloutID, nil); w.Code != 200 || !strings.Contains(w.Body.String(), dueLocation) {
			t.Fatal("activated rollout lost schedule backlink", w.Code)
		}
		// Permission replacement retires a due plan's original authority, while an
		// authorized administrator can still read why it became blocked.
		actor := "windows-schedule-review-operator"
		if _, err := h.Model.Client.User.Create().SetID(actor).SetName(actor).SetEmail(actor + "@example.test").SetUse2fa(false).SetRegister("users.completed").Save(ctx); err != nil {
			t.Fatal(err)
		}
		if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 0, []access.Grant{{Role: access.Operator, Scope: scope}}); err != nil {
			t.Fatal(err)
		}
		changed.Set("request_key", uuid.NewString())
		if w := request(actor, "POST", base+"/preview", changed); w.Code != 200 {
			t.Fatal("schedule operator preview failed", w.Code)
		}
		block, err := h.Windows.ScheduleUpdateRing(ctx, actor, scope, ring.RingID, 1, uuid.NewString(), []string{deviceID}, true, time.Now().UTC().Truncate(time.Microsecond), time.Hour, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 1, []access.Grant{{Role: access.Viewer, Scope: scope}}); err != nil {
			t.Fatal(err)
		}
		if w := request(actor, "POST", base+"/create", changed); w.Code != 403 {
			t.Fatal("preview retained stale scheduling authority", w.Code)
		}
		if w := request(actor, "POST", removalLocation+"/cancel", cancel); w.Code != 403 {
			t.Fatal("reader acquired schedule cancellation authority", w.Code)
		}
		if progress, err := h.Windows.ProcessDueUpdateSchedules(ctx, 25); err != nil || progress.Blocked != 1 {
			t.Fatal("retired scheduling authority activated work", err)
		}
		w = request("organization-admin", "GET", list+"/"+block.ID, nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "creator&#39;s permission changed") || strings.Contains(w.Body.String(), `name="confirm_cancel"`) {
			t.Fatal("blocked history hid reason or retained active form", w.Code)
		}
		artifact("windows-schedule-blocked", w)
		runConsoleBrowserFixture(t, h, ctx, os.Getenv("OPENUEM_WINDOWS_SCHEDULE_BROWSER_FIXTURE"), base+"?revision=1&mode=remove")
		after = counts()
		if _, err := h.Model.DB.ExecContext(ctx, `CREATE FUNCTION fail_windows_schedule_console_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private schedule failure'; END $$; CREATE TRIGGER fail_windows_schedule_console_audit BEFORE INSERT ON mdm_windows_update_schedule_audit FOR EACH ROW EXECUTE FUNCTION fail_windows_schedule_console_audit()`); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if _, err := h.Model.DB.ExecContext(ctx, `DROP TRIGGER fail_windows_schedule_console_audit ON mdm_windows_update_schedule_audit; DROP FUNCTION fail_windows_schedule_console_audit()`); err != nil {
					t.Error(err)
				}
			}()
			for _, path := range []string{list, removalLocation} {
				if w := request("scoped-operator", "GET", path, nil); w.Code != 503 || strings.Contains(w.Body.String(), "private schedule failure") || strings.Contains(w.Body.String(), "Schedule &lt;script&gt;source") {
					t.Fatal("unaudited schedule data escaped", path, w.Code)
				}
			}
			if w := request("scoped-operator", "POST", base+"/create", changed); w.Code != 503 || counts() != after || strings.Contains(w.Body.String(), "private schedule failure") {
				t.Fatal("failed save audit committed schedule", w.Code)
			}
			if w := request("scoped-operator", "POST", removalLocation+"/cancel", cancel); w.Code != 503 || strings.Contains(w.Body.String(), "private schedule failure") {
				t.Fatal("failed cancellation audit committed state", w.Code)
			}
		}()
		retained, err := h.Windows.UpdateScheduleDetails(ctx, "scoped-operator", scope, strings.TrimPrefix(removalLocation, list+"/"))
		if err != nil || retained.Phase != "scheduled" || retained.Revision != 1 {
			t.Fatal("cancel audit failure did not roll back full state", err)
		}
		for range 26 {
			if _, err := h.Windows.ScheduleUpdateRing(ctx, "scoped-operator", scope, ring.RingID, 1, uuid.NewString(), []string{deviceID}, true, start, time.Hour, time.Hour); err != nil {
				t.Fatal(err)
			}
		}
		if w := request("scoped-operator", "GET", list, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "?offset=25") || strings.Contains(w.Body.String(), id) {
			t.Fatal("schedule history page was not bounded", w.Code)
		}
		if w := request("scoped-operator", "GET", list+"?offset=25", nil); w.Code != 200 || !strings.Contains(w.Body.String(), id) {
			t.Fatal("older schedule history was lost", w.Code)
		}
	})
}
