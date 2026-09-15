package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func exerciseWindowsCSPExports(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, command windows.CSPCommand, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	base := fmt.Sprintf("/tenant/%d/site/%d/windows/%s/commands/%s", scope.TenantID, scope.SiteID, command.DeviceID, command.ID)
	form := func() url.Values { return url.Values{"expected_revision": {strconv.FormatInt(command.Revision, 10)}} }
	for _, actor := range []string{"organization-admin", "apple-console-admin"} {
		for _, suffix := range []string{"/export", "/observations/3/export", "/observations/14/export"} {
			w := request(actor, "POST", base+suffix, form())
			if w.Code != 200 {
				t.Fatal("evidence download unavailable", w.Code)
			}
			var document struct {
				Version      int `json:"schema_version"`
				Count        int `json:"observation_count"`
				Observations []struct {
					Message int `json:"message_id"`
				} `json:"observations"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &document); err != nil || document.Version != 1 {
				t.Fatal("download is not versioned JSON", err)
			}
			if suffix == "/export" && document.Count != 12 || suffix != "/export" && document.Count != 1 {
				t.Fatal("download scope lost")
			}
			if w.Header().Get("Content-Type") != "application/json; charset=utf-8" || !strings.HasPrefix(w.Header().Get("Content-Disposition"), `attachment; filename="windows-csp-`+command.ID) || w.Header().Get("Content-Length") != strconv.Itoa(w.Body.Len()) || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Referrer-Policy") != "strict-origin" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox") {
				t.Fatal("download privacy or framing missing")
			}
			digest := sha256.Sum256(w.Body.Bytes())
			if w.Header().Get("X-Content-SHA256") != hex.EncodeToString(digest[:]) {
				t.Fatal("attachment checksum differs")
			}
			if strings.Contains(w.Body.String(), "<script>") || !strings.Contains(w.Body.String(), `\u003cscript\u003ehistorical result`) {
				t.Fatal("device text escaped JSON boundary or vanished")
			}
		}
	}
	for _, actor := range []string{"scoped-operator", "scoped-viewer", "windows-csp-review-admin"} {
		for _, suffix := range []string{"/export", "/observations/14/export"} {
			if w := request(actor, "POST", base+suffix, form()); w.Code != 403 || strings.Contains(w.Body.String(), "historical result") {
				t.Fatal("insufficient or former authority exported", actor, w.Code)
			}
		}
	}
	for _, test := range []struct {
		name   string
		change func(url.Values)
		status int
	}{
		{"missing revision", func(f url.Values) { f.Del("expected_revision") }, 400},
		{"stale revision", func(f url.Values) { f.Set("expected_revision", "1") }, 409},
		{"noncanonical revision", func(f url.Values) { f.Set("expected_revision", "01") }, 400},
		{"duplicate revision", func(f url.Values) { f.Add("expected_revision", f.Get("expected_revision")) }, 400},
		{"query authority", func(f url.Values) { f.Set("tenant", "2") }, 400},
		{"bad CSRF", func(f url.Values) { f.Set("csrf", "wrong") }, 403},
	} {
		f := form()
		test.change(f)
		if w := request("organization-admin", "POST", base+"/export", f); w.Code != test.status || w.Header().Get("Content-Disposition") != "" {
			t.Fatal("invalid export form admitted", test.name, w.Code)
		}
	}
	for _, suffix := range []string{"/export?", "/export?expected_revision=1", "/observations/0/export", "/observations/65/export", "/observations/03/export", "/observations/bad/export"} {
		if w := request("organization-admin", "POST", base+suffix, form()); w.Code != 400 {
			t.Fatal("ambiguous export path admitted", suffix, w.Code)
		}
	}
	if w := request("organization-admin", "POST", base+"/observations/15/export", form()); w.Code != 404 {
		t.Fatal("missing evidence fabricated", w.Code)
	}
	if w := request("organization-admin", "GET", base+"/export", nil); w.Code == 200 {
		t.Fatal("GET started a protected download")
	}
	sibling, err := h.Model.Client.Site.Create().SetDescription("CSP export sibling").SetTenantID(scope.TenantID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foreign := strings.Replace(base, fmt.Sprintf("/site/%d/", scope.SiteID), fmt.Sprintf("/site/%d/", sibling.ID), 1)
	if w := request("organization-admin", "POST", foreign+"/export", form()); w.Code != 404 {
		t.Fatal("cross-site download escaped", w.Code)
	}
	hold, err := h.Model.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	if _, err := hold.Exec(`SELECT pg_advisory_xact_lock(684627957)`); err != nil {
		t.Fatal(err)
	}
	if w := request("organization-admin", "POST", base+"/export", form()); w.Code != 429 || w.Header().Get("Retry-After") != "5" || w.Header().Get("Content-Disposition") != "" {
		t.Fatal("concurrent download not bounded", w.Code)
	}
	if err := hold.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Model.DB.ExecContext(ctx, `CREATE FUNCTION fail_csp_export_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action LIKE '%exported' THEN RAISE EXCEPTION 'private export failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_csp_export_audit BEFORE INSERT ON mdm_windows_csp_audit FOR EACH ROW EXECUTE FUNCTION fail_csp_export_audit()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := h.Model.DB.ExecContext(ctx, `DROP TRIGGER fail_csp_export_audit ON mdm_windows_csp_audit`); err != nil {
			t.Error(err)
		}
	}()
	for _, suffix := range []string{"/export", "/observations/14/export"} {
		w := request("organization-admin", "POST", base+suffix, form())
		if w.Code != 503 || w.Header().Get("Content-Disposition") != "" || strings.Contains(w.Body.String(), "historical result") || strings.Contains(w.Body.String(), "private export failure") {
			t.Fatal("unaudited attachment or internal error escaped", w.Code)
		}
	}
}
