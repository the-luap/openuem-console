package handlers

import (
	"context"
	"encoding/json"
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

func windowsCSPCommandTestForm() url.Values {
	return url.Values{"request_key": {uuid.NewString()}, "seconds": {"61"}, "command": {`{"kind":"Sequence","commands":[{"kind":"Get","uri":"./DevInfo/DevId"},{"kind":"Atomic","commands":[{"kind":"Replace","uri":"./Device/Vendor/MSFT/Test/Number","format":"int","text":"0"},{"kind":"Replace","uri":"./Device/Vendor/MSFT/Test/Boolean","format":"bool","text":"false"},{"kind":"Replace","uri":"./Device/Vendor/MSFT/Test/XML","format":"xml","xml":"<x xmlns=\"urn:synthetic\"><script>literal CSP intent</script></x>"}]}]}`}}
}

func exerciseWindowsCSPForms(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, deviceOnlyID string, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	t.Run("Custom CSP creation reviews exact intent before atomic admission", func(t *testing.T) {
		deviceID, _ := windowsCSPConsolePeer(t, h, ctx, scope)
		base := fmt.Sprintf("/tenant/%d/site/%d/windows/%s/commands", scope.TenantID, scope.SiteID, deviceID)
		form := windowsCSPCommandTestForm()
		count := func() int {
			t.Helper()
			var n int
			if err := h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_windows_csp_commands WHERE device_id=$1`, deviceID).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		for _, role := range []string{"scoped-viewer", "scoped-operator"} {
			for _, path := range []string{base + "/new", base + "/preview", base + "/create"} {
				method := "POST"
				if strings.HasSuffix(path, "/new") {
					method = "GET"
				}
				if w := request(role, method, path, form); w.Code != 403 {
					t.Fatal("CSP creation authority escaped", role, path, w.Code)
				}
			}
		}
		for _, role := range []string{"organization-admin", "apple-console-admin"} {
			w := request(role, "GET", base+"/new", nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "Command tree (JSON)") || !strings.Contains(w.Body.String(), "./DevInfo/DevId") || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("CSP editor missing", w.Code)
			}
		}
		artifact("windows-csp-create-form", request("organization-admin", "GET", base+"/new", nil))
		w := request("organization-admin", "POST", base+"/preview", form)
		if w.Code != 200 || count() != 0 || !strings.Contains(w.Body.String(), "Operation 1.2.3") || !strings.Contains(w.Body.String(), ">0</pre>") || !strings.Contains(w.Body.String(), ">false</pre>") || !strings.Contains(w.Body.String(), "&lt;script&gt;literal CSP intent&lt;/script&gt;") || strings.Contains(w.Body.String(), "<script>literal CSP intent</script>") || !strings.Contains(w.Body.String(), form.Get("request_key")) || !strings.Contains(w.Body.String(), "61 seconds after confirmation") {
			t.Fatal("CSP preview changed intent or queued work", w.Code)
		}
		artifact("windows-csp-create-preview", w)
		form.Set("edit_command", "yes")
		if w := request("organization-admin", "POST", base+"/preview", form); w.Code != 200 || count() != 0 || !strings.Contains(w.Body.String(), form.Get("request_key")) || !strings.Contains(w.Body.String(), "literal CSP intent") {
			t.Fatal("editing lost command draft", w.Code)
		}
		form.Del("edit_command")
		for _, raw := range []string{`{"kind":"Get","kind":"Exec"}`, `{"kind":"Get","uri":"./Device/Vendor/MSFT/DMClient/Provider"}`, `{"kind":"Atomic","commands":[{"kind":"Get","uri":"./DevInfo/Man"}]}`} {
			bad, _ := url.ParseQuery(form.Encode())
			bad.Set("command", raw)
			w := request("organization-admin", "POST", base+"/preview", bad)
			if w.Code != 400 || !strings.Contains(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), form.Get("request_key")) || !strings.Contains(w.Body.String(), `name="command"`) || count() != 0 {
				t.Fatal("invalid CSP draft lost or admitted", w.Code)
			}
		}
		if w := request("organization-admin", "POST", base+"/create", form); w.Code != 400 || count() != 0 {
			t.Fatal("unconfirmed CSP intent queued", w.Code)
		}
		form.Set("confirm_command", "yes")
		for name, change := range map[string]func(url.Values){"repeat body": func(f url.Values) { f.Add("command", f.Get("command")) }, "csrf": func(f url.Values) { f.Set("csrf", "wrong") }, "scope": func(f url.Values) { f.Set("site", "99") }, "preview field": func(f url.Values) { f.Set("edit_command", "yes") }, "illegal tree": func(f url.Values) { f.Set("command", `{"kind":"Get","uri":"./Device/Vendor/MSFT/Enrollment/Value"}`) }} {
			bad, _ := url.ParseQuery(form.Encode())
			change(bad)
			want := 400
			if name == "csrf" {
				want = 403
			}
			if w := request("organization-admin", "POST", base+"/create", bad); w.Code != want || count() != 0 {
				t.Fatal("CSP final validation failed", name, w.Code)
			}
		}
		if w := request("organization-admin", "POST", base+"/create?seconds=60", form); w.Code != 400 || count() != 0 {
			t.Fatal("query changed CSP intent")
		}
		sibling, err := h.Model.Client.Site.Create().SetDescription("CSP creation sibling").SetTenantID(scope.TenantID).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		foreign := fmt.Sprintf("/tenant/%d/site/%d/windows/%s/commands", scope.TenantID, sibling.ID, deviceID)
		for _, action := range []string{"new", "preview", "create"} {
			method := "POST"
			if action == "new" {
				method = "GET"
			}
			if w := request("organization-admin", method, foreign+"/"+action, form); w.Code != 404 {
				t.Fatal("foreign device accepted CSP draft", w.Code)
			}
		}
		userForm, _ := url.ParseQuery(form.Encode())
		userForm.Set("command", `{"kind":"Replace","uri":"./User/Vendor/MSFT/Test/Value","format":"chr","text":""}`)
		if w := request("organization-admin", "POST", base+"/preview", userForm); w.Code != 200 || !strings.Contains(w.Body.String(), "eligible enrolled-user session") || !strings.Contains(w.Body.String(), "Empty value") {
			t.Fatal("Full enrollment lost user-target preview", w.Code)
		}
		deviceOnly := fmt.Sprintf("/tenant/%d/site/%d/windows/%s/commands", scope.TenantID, scope.SiteID, deviceOnlyID)
		for _, action := range []string{"preview", "create"} {
			if w := request("organization-admin", "POST", deviceOnly+"/"+action, userForm); w.Code != 400 {
				t.Fatal("device enrollment admitted user targets", w.Code)
			}
		}
		if _, err := h.Model.DB.ExecContext(ctx, `CREATE FUNCTION fail_windows_csp_create_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private CSP creation error'; END $$; CREATE TRIGGER fail_windows_csp_create_audit BEFORE INSERT ON mdm_windows_csp_audit FOR EACH ROW EXECUTE FUNCTION fail_windows_csp_create_audit()`); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if _, err := h.Model.DB.ExecContext(ctx, `DROP TRIGGER fail_windows_csp_create_audit ON mdm_windows_csp_audit; DROP FUNCTION fail_windows_csp_create_audit()`); err != nil {
					t.Error(err)
				}
			}()
			if w := request("organization-admin", "POST", base+"/create", form); w.Code != 503 || count() != 0 || strings.Contains(w.Body.String(), "private CSP creation error") {
				t.Fatal("failed audit preserved partial CSP admission", w.Code)
			}
		}()
		w = request("organization-admin", "POST", base+"/create", form)
		location := w.Header().Get("Location")
		if w.Code != 303 || !strings.HasPrefix(location, base+"/") || count() != 1 {
			t.Fatal("confirmed CSP command not admitted exactly once", w.Code)
		}
		id := strings.TrimPrefix(location, base+"/")
		saved, err := h.Windows.CSPCommandDetails(ctx, "organization-admin", scope, deviceID, id)
		if err != nil || saved.Command.Phase != "queued" || saved.Command.ExpiresAt.Sub(saved.Command.CreatedAt) != 61*time.Second || len(saved.Request.Commands) != 2 || len(saved.Request.Commands[1].Commands) != 3 || saved.Request.Commands[1].Commands[0].Items[0].Data.Text != "0" || saved.Request.Commands[1].Commands[1].Items[0].Data.Text != "false" {
			t.Fatal("saved CSP intent differs from preview", err)
		}
		for range 3 {
			if w := request("organization-admin", "POST", base+"/create", form); w.Code != 303 || w.Header().Get("Location") != location || count() != 1 {
				t.Fatal("confirmed retry duplicated command", w.Code)
			}
		}
		reordered, _ := url.ParseQuery(form.Encode())
		var tree any
		if err := json.Unmarshal([]byte(form.Get("command")), &tree); err != nil {
			t.Fatal(err)
		}
		pretty, _ := json.MarshalIndent(tree, "", "  ")
		reordered.Set("command", string(pretty))
		if w := request("organization-admin", "POST", base+"/create", reordered); w.Code != 303 || w.Header().Get("Location") != location || count() != 1 {
			t.Fatal("equivalent JSON lost idempotency", w.Code)
		}
		reordered.Set("seconds", "62")
		if w := request("organization-admin", "POST", base+"/create", reordered); w.Code != 409 || count() != 1 {
			t.Fatal("reused request changed lifetime", w.Code)
		}
		reordered.Set("seconds", "61")
		reordered.Set("command", `{"kind":"Get","uri":"./DevInfo/Man"}`)
		if w := request("organization-admin", "POST", base+"/create", reordered); w.Code != 409 || count() != 1 {
			t.Fatal("reused request changed command", w.Code)
		}
		// This payload needs more than the legacy 8 KiB form while fitting the
		// unchanged compiler limit. Escaping doubles its JSON size exactly.
		large := windowsCSPCommandTestForm()
		value := strings.Repeat("\\", 100000)
		encoded, _ := json.Marshal(map[string]string{"kind": "Replace", "uri": "./Device/Vendor/MSFT/Test/Large", "format": "chr", "text": value})
		large.Set("command", string(encoded))
		large.Set("confirm_command", "yes")
		if w := request("organization-admin", "POST", base+"/preview", large); w.Code != 200 {
			t.Fatal("valid large command could not be reviewed", w.Code)
		}
		if w := request("organization-admin", "POST", base+"/create", large); w.Code != 303 || count() != 2 {
			t.Fatal("valid large command could not be admitted", w.Code)
		}
		actor := "windows-csp-create-admin"
		if _, err := h.Model.Client.User.Create().SetID(actor).SetName(actor).SetEmail(actor + "@example.test").SetUse2fa(false).SetRegister("users.completed").Save(ctx); err != nil {
			t.Fatal(err)
		}
		if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 0, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: scope.TenantID}}}); err != nil {
			t.Fatal(err)
		}
		if w := request(actor, "POST", base+"/preview", form); w.Code != 200 {
			t.Fatal("reviewing administrator denied", w.Code)
		}
		if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 1, []access.Grant{{Role: access.Viewer, Scope: scope}}); err != nil {
			t.Fatal(err)
		}
		fresh := windowsCSPCommandTestForm()
		fresh.Set("confirm_command", "yes")
		if w := request(actor, "POST", base+"/create", fresh); w.Code != 403 || count() != 2 {
			t.Fatal("preview retained stale administrator authority", w.Code)
		}
		runConsoleBrowserFixture(t, h, ctx, os.Getenv("OPENUEM_WINDOWS_CSP_CREATE_BROWSER_FIXTURE"), base+"/new")
		// Fill only this owned device's queue; browser acceptance may have added
		// another command. Its canceled/terminal commands do not consume capacity.
		var pending int
		if err := h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_windows_csp_commands WHERE device_id=$1 AND phase IN ('queued','blocked','sent','unknown')`, deviceID).Scan(&pending); err != nil {
			t.Fatal(err)
		}
		for ; pending < 256; pending++ {
			if _, err := h.Windows.EnqueueCSPCommand(ctx, "organization-admin", scope, deviceID, uuid.NewString(), windows.CSPCommandSpec{Kind: "Get", URI: "./DevInfo/Man"}, time.Hour); err != nil {
				t.Fatal(err)
			}
		}
		before := count()
		if w := request("organization-admin", "POST", base+"/create", fresh); w.Code != 409 || count() != before {
			t.Fatal("full queue admitted new command", w.Code)
		}
		if err := h.Windows.RevokeDevice(ctx, "organization-admin", scope, deviceID); err != nil {
			t.Fatal(err)
		}
		if w := request("organization-admin", "GET", base+"/new", nil); w.Code != 409 {
			t.Fatal("revoked identity opened new command form", w.Code)
		}
		if w := request("organization-admin", "POST", base+"/create", fresh); w.Code != 409 || count() != before {
			t.Fatal("revoked identity admitted new command", w.Code)
		}
		if w := request("organization-admin", "POST", base+"/create", form); w.Code != 303 || w.Header().Get("Location") != location || count() != before {
			t.Fatal("exact retry lost admitted identity after revocation", w.Code)
		}
	})
}
