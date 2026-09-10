package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
)

func exerciseWindowsAuditConsole(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder), field func(*httptest.ResponseRecorder, string) string) {
	t.Helper()
	t.Run("Windows audit sources and explicitly reviewed retention", func(t *testing.T) {
		base := fmt.Sprintf("/tenant/%d/audit", tenant)
		scope := access.Scope{TenantID: tenant}
		tables := map[string]string{"windows_enrollment": "mdm_windows_audit", "windows_authority": "mdm_windows_authority_audit", "windows_management": "mdm_windows_management_audit", "windows_csp": "mdm_windows_csp_audit", "windows_updates": "mdm_windows_update_audit", "windows_rings": "mdm_windows_update_ring_audit", "windows_schedules": "mdm_windows_update_schedule_audit", "windows_console": "mdm_windows_console_audit", "windows_renewal": "mdm_windows_renewal_audit", "windows_unenrollment": "mdm_windows_unenrollment_audit", "windows_disconnection_requests": "mdm_windows_unenrollment_request_audit", "windows_certificate_reminders": "mdm_windows_certificate_reminder_audit"}
		type oldEvent struct {
			id     int64
			tenant int
		}
		old := map[string]oldEvent{}
		var cspCommand string
		for source, table := range tables {
			w := request("organization-admin", "GET", base+"?source="+source, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), audit.SourceLabel(source)) {
				t.Fatal("Windows audit source unavailable", source, w.Code)
			}
			f := audit.Filter{Scope: scope, Source: source, From: time.Now().Add(-24 * time.Hour), Until: time.Now().Add(time.Minute)}
			page, err := h.Audit.List(ctx, "organization-admin", f, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Events) == 0 {
				// Renewal fixtures have their own organization; retain that
				// historical scope instead of manufacturing local ownership.
				f.Scope = access.Scope{}
				page, err = h.Audit.List(ctx, "apple-console-admin", f, "")
				if err != nil || len(page.Events) == 0 {
					t.Fatal("real Windows schema produced no audit source", source, err)
				}
				f.Scope = access.Scope{TenantID: page.Events[0].TenantID}
				page, err = h.Audit.List(ctx, "apple-console-admin", f, "")
				if err != nil {
					t.Fatal(err)
				}
			}
			sourceBase := fmt.Sprintf("/tenant/%d/audit", f.Scope.TenantID)
			if source == "windows_csp" {
				cspCommand = page.Events[0].Resource
				artifact("windows-audit-csp", w)
			}
			for _, event := range page.Events {
				if event.TenantID != f.Scope.TenantID || event.Result != "recorded" {
					t.Fatal("Windows audit scope or meaning changed")
				}
			}
			for _, actor := range []string{"scoped-viewer", "scoped-operator"} {
				if w := request(actor, "GET", base+"?source="+source, nil); w.Code != 403 {
					t.Fatal("reader reached Windows audit", w.Code)
				}
			}
			// Add an old audit event using a real source row and its immutable
			// parent. No device, command or cryptographic state is changed.
			var columns, values string
			if err := h.Model.DB.QueryRow(`SELECT string_agg(quote_ident(attname),',' ORDER BY attnum),string_agg(CASE WHEN attname='created_at' THEN 'clock_timestamp()-interval ''40 days''' ELSE quote_ident(attname) END,',' ORDER BY attnum) FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped AND attname<>'id' AND attgenerated=''`, table).Scan(&columns, &values); err != nil {
				t.Fatal(err)
			}
			var id int64
			if err := h.Model.DB.QueryRow(`INSERT INTO `+table+`(`+columns+`) SELECT `+values+` FROM `+table+` WHERE id=$1 RETURNING id`, page.Events[0].ID).Scan(&id); err != nil {
				t.Fatal(err)
			}
			old[table] = oldEvent{id: id, tenant: f.Scope.TenantID}
			if _, err := h.Model.DB.Exec(`DELETE FROM `+table+` WHERE id=$1`, id); err == nil {
				t.Fatal("real audit guard permitted unreceipted deletion", source)
			}
			v := url.Values{"csrf": {"console-test-token"}, "source": {source}, "format": {"json"}}
			w = request("apple-console-admin", "POST", sourceBase+"/export", v)
			if w.Code != 200 || !strings.Contains(w.Body.String(), source) || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
				t.Fatal("Windows audit metadata export unavailable", source, w.Code)
			}
			var events []audit.Event
			if err := json.Unmarshal(w.Body.Bytes(), &events); err != nil {
				t.Fatal(err)
			}
			for _, event := range events {
				if event.Source != source || event.TenantID != f.Scope.TenantID {
					t.Fatal("Windows metadata export widened source/scope")
				}
			}
		}
		// The previously confirmed legacy policy must leave every Windows row.
		if err := h.Audit.PruneRetention(ctx); err != nil {
			t.Fatal(err)
		}
		for table, event := range old {
			var found bool
			if err := h.Model.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM `+table+` WHERE id=$1)`, event.id).Scan(&found); err != nil || !found {
				t.Fatal("legacy policy deleted a Windows event", table, err)
			}
		}
		var device string
		var actualSite int
		if err := h.Model.DB.QueryRow(`SELECT device_id,site_id FROM mdm_windows_csp_commands WHERE id=$1`, cspCommand).Scan(&device, &actualSite); err != nil {
			t.Fatal(err)
		}
		deviceScope := access.Scope{TenantID: tenant, SiteID: actualSite}
		command, err := h.Windows.CSPCommand(ctx, "organization-admin", deviceScope, device, cspCommand)
		if err != nil {
			t.Fatal(err)
		}
		evidence := func() map[string]any {
			t.Helper()
			data, err := h.Windows.ExportCSPCommand(ctx, "organization-admin", deviceScope, device, cspCommand, command.Revision, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(data.Data)
			var value map[string]any
			if err := json.Unmarshal(data.Data, &value); err != nil {
				t.Fatal(err)
			}
			delete(value, "audit_id")
			delete(value, "exported_at")
			return value
		}
		before := evidence()
		for _, invalid := range []url.Values{{"csrf": {"console-test-token"}, "days": {"30"}, "include_windows": {"no"}}, {"csrf": {"console-test-token"}, "days": {"30"}, "include_windows": {"yes", "yes"}}} {
			if w := request("organization-admin", "POST", base+"/retention/preview", invalid); w.Code != 400 {
				t.Fatal("ambiguous Windows retention choice accepted", w.Code)
			}
		}
		v := url.Values{"csrf": {"console-test-token"}, "days": {"30"}, "include_windows": {"yes"}}
		if w := request("apple-console-admin", "POST", "/audit/retention/preview", v); w.Code != 400 {
			t.Fatal("global policy acquired Windows deletion", w.Code)
		}
		w := request("organization-admin", "POST", base+"/retention/preview", v)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Windows audit events follow this policy") || !strings.Contains(w.Body.String(), "Windows certificate reminders") {
			t.Fatal("Windows retention preview omitted its scope", w.Code)
		}
		artifact("windows-audit-retention-preview", w)
		apply := url.Values{"csrf": {"console-test-token"}, "preview": {field(w, "preview")}, "token": {field(w, "token")}}
		if w := request("organization-admin", "POST", base+"/retention/apply", apply); w.Code != 400 {
			t.Fatal("Windows retention lacked confirmation", w.Code)
		}
		apply.Set("confirm", "yes")
		apply.Set("include_windows", "yes")
		if w := request("organization-admin", "POST", base+"/retention/apply", apply); w.Code != 400 {
			t.Fatal("confirmation allowed replacing stored choice", w.Code)
		}
		apply.Del("include_windows")
		if w := request("organization-admin", "POST", base+"/retention/apply", apply); w.Code != 303 {
			t.Fatal("reviewed Windows retention failed", w.Code)
		}
		if err := h.Audit.PruneRetention(ctx); err != nil {
			t.Fatal("real Windows audit schema could not prune", err)
		}
		for table, event := range old {
			var found bool
			if err := h.Model.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM `+table+` WHERE id=$1)`, event.id).Scan(&found); err != nil || found != (event.tenant != tenant) {
				t.Fatal("confirmed retention crossed its organization or retained eligible events", table, err)
			}
		}
		otherTenants := map[int]bool{}
		for _, event := range old {
			if event.tenant != tenant {
				otherTenants[event.tenant] = true
			}
		}
		for otherTenant := range otherTenants {
			otherScope := access.Scope{TenantID: otherTenant}
			preview, err := h.Audit.PreviewRetentionWithWindows(ctx, "apple-console-admin", otherScope, 30, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := h.Audit.ApplyRetention(ctx, "apple-console-admin", otherScope, preview.ID, preview.Token); err != nil {
				t.Fatal(err)
			}
			if err := h.Audit.PruneRetention(ctx); err != nil {
				t.Fatal(err)
			}
		}
		for table, event := range old {
			var found bool
			if err := h.Model.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM `+table+` WHERE id=$1)`, event.id).Scan(&found); err != nil || found {
				t.Fatal("real source could not follow its independent policy", table, err)
			}
		}
		if after := evidence(); !reflect.DeepEqual(before, after) {
			t.Fatal("audit retention changed command or observation evidence")
		}
		w = request("organization-admin", "GET", base+"/retention", nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "retention.prune") || !strings.Contains(w.Body.String(), "Windows CSP commands") {
			t.Fatal("Windows deletion receipts not visible", w.Code)
		}
		artifact("windows-audit-retention-history", w)
		preview, err := h.Audit.PreviewRetentionWithWindows(ctx, "organization-admin", scope, 0, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Audit.ApplyRetention(ctx, "organization-admin", scope, preview.ID, preview.Token); err != nil {
			t.Fatal(err)
		}
		if fixture := os.Getenv("OPENUEM_WINDOWS_AUDIT_BROWSER_FIXTURE"); fixture != "" {
			runConsoleBrowserFixture(t, h, ctx, fixture, base+"?source=windows_csp")
		}
	})
}
