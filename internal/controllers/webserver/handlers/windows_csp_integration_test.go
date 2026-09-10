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

func exerciseWindowsCSPConsole(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	t.Run("Windows CSP console preserves protected evidence and cancellation boundaries", func(t *testing.T) {
		deviceID, deliver := windowsCSPConsolePeer(t, h, ctx, scope)
		base := fmt.Sprintf("/tenant/%d/site/%d/windows/%s", scope.TenantID, scope.SiteID, deviceID)
		list := base + "/commands"
		spec := windows.CSPCommandSpec{Kind: "Get", URI: "./Device/Vendor/MSFT/Policy/Result/Update/DeferQualityUpdatesPeriodInDays"}
		completed := deliver(spec, "200")
		if completed.Command.Phase != "acknowledged" || len(completed.Outcomes) != 1 || completed.Outcomes[0].Data == nil {
			t.Fatal("synthetic protocol did not produce complete evidence")
		}
		path := list + "/" + completed.Command.ID
		w := request("organization-admin", "GET", path, nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Command acknowledged") || !strings.Contains(w.Body.String(), "&lt;script&gt;device result&lt;/script&gt;") || strings.Contains(w.Body.String(), "<script>device result</script>") || strings.Contains(w.Body.String(), `name="confirm_cancel"`) || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("protected correlated CSP evidence unavailable", w.Code)
		}
		artifact("windows-csp-complete", w)
		unknown := deliver(windows.CSPCommandSpec{Kind: "Exec", URI: "./Device/Vendor/MSFT/Test/Run"}, "202")
		if unknown.Command.Phase != "unknown" {
			t.Fatal("asynchronous acceptance lost uncertainty")
		}
		unknownPath := list + "/" + unknown.Command.ID
		cancel := url.Values{"expected_revision": {fmt.Sprint(unknown.Command.Revision)}, "confirm_cancel": {"yes"}}
		abandon := url.Values{"expected_revision": {fmt.Sprint(unknown.Command.Revision)}, "confirm_abandon": {"yes"}, "resolution": {"Reviewed synthetic <script>evidence</script>; accept unresolved effects"}}
		for _, user := range []string{"scoped-operator", "scoped-viewer"} {
			for _, path := range []string{list, unknownPath, unknownPath + "/cancel", unknownPath + "/abandon"} {
				method := "GET"
				form := cancel
				if strings.HasSuffix(path, "/cancel") || strings.HasSuffix(path, "/abandon") {
					method = "POST"
				}
				if strings.HasSuffix(path, "/abandon") {
					form = abandon
				}
				if w := request(user, method, path, form); w.Code != 403 {
					t.Fatal("CSP administrator boundary failed", user, path, w.Code)
				}
			}
			if w := request(user, "GET", base, nil); w.Code != 200 || strings.Contains(w.Body.String(), "Windows CSP commands") {
				t.Fatal("CSP navigation exposed to nonadministrator", user, w.Code)
			}
		}
		for _, path := range []string{list, unknownPath} {
			if w := request("apple-console-admin", "GET", path, nil); w.Code != 200 || !strings.Contains(w.Body.String(), unknown.Command.ID) {
				t.Fatal("server administrator lost CSP history", w.Code)
			}
		}
		artifact("windows-csp-unknown", request("organization-admin", "GET", unknownPath, nil))
		actor := "windows-csp-review-admin"
		if _, err := h.Model.Client.User.Create().SetID(actor).SetName(actor).SetEmail(actor + "@example.test").SetUse2fa(false).Save(ctx); err != nil {
			t.Fatal(err)
		}
		if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 0, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: scope.TenantID}}}); err != nil {
			t.Fatal(err)
		}
		if w := request(actor, "GET", unknownPath, nil); w.Code != 200 {
			t.Fatal("reviewing administrator denied", w.Code)
		}
		if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 1, []access.Grant{{Role: access.Viewer, Scope: scope}}); err != nil {
			t.Fatal(err)
		}
		if w := request(actor, "POST", unknownPath+"/abandon", abandon); w.Code != 403 {
			t.Fatal("review retained old administrative authority", w.Code)
		}
		if w := request("organization-admin", "POST", unknownPath+"/cancel", cancel); w.Code != 409 {
			t.Fatal("uncertain command canceled", w.Code)
		}
		for name, change := range map[string]func(url.Values){"unconfirmed": func(f url.Values) { f.Del("confirm_abandon") }, "repeat revision": func(f url.Values) { f.Add("expected_revision", f.Get("expected_revision")) }, "blank note": func(f url.Values) { f.Set("resolution", "") }, "multibyte note": func(f url.Values) { f.Set("resolution", strings.Repeat("ä", 161)) }, "scope": func(f url.Values) { f.Set("site", "99") }, "csrf": func(f url.Values) { f.Set("csrf", "wrong") }, "stale": func(f url.Values) { f.Set("expected_revision", "1") }} {
			f, _ := url.ParseQuery(abandon.Encode())
			change(f)
			want := 400
			if name == "csrf" {
				want = 403
			}
			if name == "stale" {
				want = 409
			}
			if w := request("organization-admin", "POST", unknownPath+"/abandon", f); w.Code != want {
				t.Fatal("invalid CSP resolution admitted", name, w.Code)
			}
		}
		sibling, err := h.Model.Client.Site.Create().SetDescription("CSP console sibling").SetTenantID(scope.TenantID).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		foreign := fmt.Sprintf("/tenant/%d/site/%d/windows/%s/commands/%s", scope.TenantID, sibling.ID, deviceID, unknown.Command.ID)
		for _, suffix := range []string{"", "/cancel", "/abandon"} {
			method := "GET"
			f := cancel
			if suffix != "" {
				method = "POST"
			}
			if suffix == "/abandon" {
				f = abandon
			}
			if w := request("organization-admin", method, foreign+suffix, f); w.Code != 404 {
				t.Fatal("foreign scope accessed CSP evidence", w.Code)
			}
		}
		for _, id := range []string{"invalid", uuid.NewString()} {
			want := 404
			if id == "invalid" {
				want = 400
			}
			if w := request("organization-admin", "GET", list+"/"+id, nil); w.Code != want {
				t.Fatal("invalid command identity admitted", w.Code)
			}
		}
		for _, query := range []string{"?offset=-1", "?offset=01", "?offset=1&offset=2", "?offset=100001"} {
			if w := request("organization-admin", "GET", list+query, nil); w.Code != 400 {
				t.Fatal("invalid CSP page admitted", w.Code)
			}
		}
		queue := func() *windows.CSPCommand {
			t.Helper()
			command, err := h.Windows.EnqueueCSPCommand(ctx, "organization-admin", scope, deviceID, uuid.NewString(), spec, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			return command
		}
		queued := queue()
		queuedPath := list + "/" + queued.ID
		queuedCancel := url.Values{"expected_revision": {"1"}, "confirm_cancel": {"yes"}}
		if _, err := h.Model.DB.ExecContext(ctx, `CREATE FUNCTION fail_windows_csp_console_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private CSP console failure'; END $$; CREATE TRIGGER fail_windows_csp_console_audit BEFORE INSERT ON mdm_windows_csp_audit FOR EACH ROW EXECUTE FUNCTION fail_windows_csp_console_audit()`); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if _, err := h.Model.DB.ExecContext(ctx, `DROP TRIGGER fail_windows_csp_console_audit ON mdm_windows_csp_audit; DROP FUNCTION fail_windows_csp_console_audit()`); err != nil {
					t.Error(err)
				}
			}()
			for _, path := range []string{list, unknownPath} {
				if w := request("organization-admin", "GET", path, nil); w.Code != 503 || strings.Contains(w.Body.String(), unknown.Command.ID) || strings.Contains(w.Body.String(), "private CSP console failure") {
					t.Fatal("unaudited CSP data escaped", w.Code)
				}
			}
			// Reads now pass, so cancellation reaches its final write audit rather
			// than stopping at the handler's protected immutable-owner lookup.
			if _, err := h.Model.DB.ExecContext(ctx, `CREATE OR REPLACE FUNCTION fail_windows_csp_console_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('command.canceled','command.abandoned') THEN RAISE EXCEPTION 'private CSP console failure'; END IF; RETURN NEW; END $$`); err != nil {
				t.Fatal(err)
			}
			for path, f := range map[string]url.Values{unknownPath + "/abandon": abandon, queuedPath + "/cancel": queuedCancel} {
				if w := request("organization-admin", "POST", path, f); w.Code != 503 {
					t.Fatal("failed audit admitted CSP mutation", w.Code)
				}
			}
		}()
		if d, err := h.Windows.CSPCommandDetails(ctx, "organization-admin", scope, deviceID, unknown.Command.ID); err != nil || d.Command.Phase != "unknown" || d.Command.Revision != unknown.Command.Revision || d.Resolution != "" {
			t.Fatal("resolution audit failure did not roll back", err)
		}
		if d, err := h.Windows.CSPCommand(ctx, "organization-admin", scope, deviceID, queued.ID); err != nil || d.Phase != "queued" || d.Revision != 1 {
			t.Fatal("cancellation audit failure did not roll back", err)
		}
		if w := request("organization-admin", "POST", unknownPath+"/abandon?resolution=override", abandon); w.Code != 400 {
			t.Fatal("resolution query admitted")
		}
		if w := request("organization-admin", "POST", unknownPath+"/abandon", abandon); w.Code != 303 || w.Header().Get("Location") != unknownPath {
			t.Fatal("reviewed resolution failed", w.Code)
		}
		w = request("organization-admin", "GET", unknownPath, nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Uncertain command released") || !strings.Contains(w.Body.String(), "&lt;script&gt;evidence&lt;/script&gt;") || strings.Contains(w.Body.String(), `name="confirm_abandon"`) {
			t.Fatal("released uncertainty history incorrect", w.Code)
		}
		artifact("windows-csp-abandoned", w)
		if w := request("organization-admin", "POST", unknownPath+"/abandon", abandon); w.Code != 409 {
			t.Fatal("stale resolution changed terminal history")
		}
		for _, f := range []url.Values{{"expected_revision": {"1"}}, {"expected_revision": {"2"}, "confirm_cancel": {"yes"}}, {"expected_revision": {"1"}, "confirm_cancel": {"yes"}, "csrf": {"wrong"}}} {
			want := 400
			if f.Get("expected_revision") == "2" {
				want = 409
			}
			if f.Get("csrf") == "wrong" {
				want = 403
			}
			if w := request("organization-admin", "POST", queuedPath+"/cancel", f); w.Code != want {
				t.Fatal("invalid cancellation admitted", w.Code)
			}
		}
		artifact("windows-csp-queued", request("organization-admin", "GET", queuedPath, nil))
		if w := request("organization-admin", "POST", queuedPath+"/cancel", queuedCancel); w.Code != 303 || w.Header().Get("Location") != queuedPath {
			t.Fatal("queued cancellation failed", w.Code)
		}
		if w := request("organization-admin", "GET", queuedPath, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Canceled before delivery") || strings.Contains(w.Body.String(), `name="confirm_cancel"`) {
			t.Fatal("canceled history lost", w.Code)
		}
		zero := 0
		run, err := h.Windows.EnqueueUpdatePolicy(ctx, "scoped-operator", scope, deviceID, uuid.NewString(), "CSP owner test", windows.UpdatePolicy{QualityDeferralDays: &zero}, false, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		typed, err := h.Windows.UpdateRunDetails(ctx, "scoped-operator", scope, deviceID, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		stepPath := list + "/" + typed.Steps[0].ID
		if w := request("organization-admin", "GET", stepPath, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Open owning update policy run") || strings.Contains(w.Body.String(), `name="confirm_cancel"`) {
			t.Fatal("typed step bypassed owning run", w.Code)
		}
		if w := request("organization-admin", "POST", stepPath+"/cancel", queuedCancel); w.Code != 409 {
			t.Fatal("raw action bypassed typed run cancellation", w.Code)
		}
		for range 26 {
			queue()
		}
		if w := request("organization-admin", "GET", list, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "?offset=25") || strings.Contains(w.Body.String(), completed.Command.ID) {
			t.Fatal("unbounded command page", w.Code)
		}
		if w := request("organization-admin", "GET", list+"?offset=25", nil); w.Code != 200 || !strings.Contains(w.Body.String(), completed.Command.ID) {
			t.Fatal("older CSP evidence lost", w.Code)
		}
		artifact("windows-csp-commands", request("organization-admin", "GET", list, nil))
		if fixture := os.Getenv("OPENUEM_WINDOWS_CSP_BROWSER_FIXTURE"); fixture != "" {
			browserDevice, browserDeliver := windowsCSPConsolePeer(t, h, ctx, scope)
			browserUnknown := browserDeliver(windows.CSPCommandSpec{Kind: "Exec", URI: "./Device/Vendor/MSFT/Test/Run"}, "202")
			if _, err := h.Windows.EnqueueCSPCommand(ctx, "organization-admin", scope, browserDevice, uuid.NewString(), spec, time.Hour); err != nil {
				t.Fatal(err)
			}
			entry := fmt.Sprintf("/tenant/%d/site/%d/windows/%s/commands/%s", scope.TenantID, scope.SiteID, browserDevice, browserUnknown.Command.ID)
			runConsoleBrowserFixture(t, h, ctx, fixture, entry)
		}
	})
}
