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

func exerciseWindowsCSPObservations(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	t.Run("protected Windows CSP observation chronology", func(t *testing.T) {
		deviceID, deliver := windowsCSPConsolePeer(t, h, ctx, scope)
		completed := deliver(windows.CSPCommandSpec{Kind: "Get", URI: "./DevDetail/SwV"}, "chunks")
		base := fmt.Sprintf("/tenant/%d/site/%d/windows/%s/commands/%s", scope.TenantID, scope.SiteID, deviceID, completed.Command.ID)
		exerciseWindowsCSPExports(t, h, ctx, scope, completed.Command, request)
		path := base + "/observations"
		for _, actor := range []string{"organization-admin", "apple-console-admin"} {
			w := request(actor, "GET", path, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "?offset=10") || !strings.Contains(w.Body.String(), "Open message 3") || strings.Contains(w.Body.String(), "Open message 14") || strings.Contains(w.Body.String(), "historical result") {
				t.Fatal("history did not bound or protect values", w.Code)
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "strict-origin" {
				t.Fatal("history privacy headers missing")
			}
			artifact("windows-csp-observations", w)
		}
		w := request("organization-admin", "GET", path+"?offset=10", nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Open message 14") || strings.Contains(w.Body.String(), "Next observations") || !strings.Contains(w.Body.String(), "Command acknowledged") {
			t.Fatal("final history page lost completion", w.Code)
		}
		artifact("windows-csp-observations-last", w)
		w = request("organization-admin", "GET", path+"/3", nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Evidence incomplete") || !strings.Contains(w.Body.String(), "Incomplete result; partial value withheld.") || strings.Contains(w.Body.String(), "Text value") || strings.Contains(w.Body.String(), "Command acknowledged") {
			t.Fatal("earlier snapshot acquired later outcome", w.Code)
		}
		artifact("windows-csp-observation-partial", w)
		w = request("organization-admin", "GET", path+"/14", nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "&lt;script&gt;historical result&lt;/script&gt;") || strings.Contains(w.Body.String(), "<script>historical result</script>") || !strings.Contains(w.Body.String(), "Command acknowledged") {
			t.Fatal("complete snapshot escaped or lost values", w.Code)
		}
		artifact("windows-csp-observation-complete", w)
		for _, actor := range []string{"scoped-operator", "scoped-viewer", "windows-csp-review-admin"} {
			for _, suffix := range []string{"", "/14"} {
				if w := request(actor, "GET", path+suffix, nil); w.Code != 403 {
					t.Fatal("history reused former or insufficient authority", actor, w.Code)
				}
			}
		}
		for _, suffix := range []string{"?", "?offset", "?offset=", "?offset=%zz", "?offset=1;extra=2", "?offset=-1", "?offset=01", "?offset=65", "?offset=1&offset=2", "?other=1", "/0", "/65", "/03", "/bad", "/3?offset=0"} {
			if w := request("organization-admin", "GET", path+suffix, nil); w.Code != 400 {
				t.Fatal("invalid history request admitted", suffix, w.Code)
			}
		}
		if w := request("organization-admin", "GET", path+"/15", nil); w.Code != 404 {
			t.Fatal("absent snapshot invented", w.Code)
		}
		sibling, err := h.Model.Client.Site.Create().SetDescription("CSP observation sibling").SetTenantID(scope.TenantID).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		foreign := strings.Replace(path, fmt.Sprintf("/site/%d/", scope.SiteID), fmt.Sprintf("/site/%d/", sibling.ID), 1)
		for _, suffix := range []string{"", "/14"} {
			if w := request("organization-admin", "GET", foreign+suffix, nil); w.Code != 404 {
				t.Fatal("cross-site history escaped", w.Code)
			}
		}
		if _, err := h.Model.DB.ExecContext(ctx, `CREATE FUNCTION fail_csp_observation_console_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private observation failure'; END $$; CREATE TRIGGER fail_csp_observation_console_audit BEFORE INSERT ON mdm_windows_csp_audit FOR EACH ROW EXECUTE FUNCTION fail_csp_observation_console_audit()`); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if _, err := h.Model.DB.ExecContext(ctx, `DROP TRIGGER fail_csp_observation_console_audit ON mdm_windows_csp_audit`); err != nil {
					t.Error(err)
				}
			}()
			for _, suffix := range []string{"", "/14"} {
				w := request("organization-admin", "GET", path+suffix, nil)
				if w.Code != 503 || strings.Contains(w.Body.String(), "historical result") || strings.Contains(w.Body.String(), "private observation failure") {
					t.Fatal("unaudited observation escaped", w.Code)
				}
			}
		}()
		queued, err := h.Windows.EnqueueCSPCommand(ctx, "organization-admin", scope, deviceID, uuid.NewString(), windows.CSPCommandSpec{Kind: "Get", URI: "./DevInfo/Man"}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		empty := strings.Replace(path, completed.Command.ID, queued.ID, 1)
		if w := request("organization-admin", "GET", empty, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "No stored observations in this view.") {
			t.Fatal("empty history fabricated evidence", w.Code)
		}
		if fixture := os.Getenv("OPENUEM_WINDOWS_CSP_OBSERVATION_BROWSER_FIXTURE"); fixture != "" {
			runConsoleBrowserFixture(t, h, ctx, fixture, base)
		}
		if err := h.Windows.RevokeDevice(ctx, "organization-admin", scope, deviceID); err != nil {
			t.Fatal(err)
		}
		for _, suffix := range []string{"", "/3", "/14"} {
			if w := request("organization-admin", "GET", path+suffix, nil); w.Code != 200 {
				t.Fatal("revocation erased protected history", w.Code)
			}
		}
	})
}
