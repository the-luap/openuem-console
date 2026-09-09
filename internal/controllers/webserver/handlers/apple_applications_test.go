package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func exerciseAppleApplications(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	org := fmt.Sprintf("/tenant/%d/software/catalog", tenant)
	scoped := fmt.Sprintf("/tenant/%d/site/%d", tenant, site)
	device := uuid.NewString()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := h.Model.DB.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO mdm_apple_devices(id,tenant_id,site_id,name,status,model,os_version,enrollment_method,enrollment_platform,invite_expires_at,certificate_expires_at,inventory_at) VALUES($1,$2,$3,'Application route Mac','enrolled','Mac16,1','15.0','manual_device','macos',clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 year',clock_timestamp())`, device, tenant, site)
	exec(`INSERT INTO mdm_apple_enrollment_layouts(device_id,tenant_id,profile_uuid,mdm_uuid,identity_uuid,identity_type,public_url,topic,access_rights) VALUES($1,$2,$3,$4,$5,'com.apple.security.scep','https://mdm.example.test','com.apple.mgmt.test',7955)`, device, tenant, uuid.NewString(), uuid.NewString(), uuid.NewString())
	packageForm := func() url.Values {
		return url.Values{"name": {"Route <Editor>"}, "identifier": {"com.example.RouteEditor"}, "version": {"42.0"}, "architecture": {"universal"}, "minimum_os": {"14.0"}, "sha256": {strings.Repeat("a", 64)}, "source_url": {"https://packages.example.test/editor.pkg?secret=route-download-secret"}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", scoped+"/software/catalog", packageForm()); rec.Code != 403 {
			t.Fatal("scoped role published executable content", user, rec.Code)
		}
	}
	for _, change := range []func(url.Values){func(f url.Values) { f.Del("confirmed") }, func(f url.Values) { f.Add("source_url", "https://example.test/other.pkg") }, func(f url.Values) { f.Set("payload", "unapproved") }, func(f url.Values) { f.Set("single_app", "true") }} {
		f := packageForm()
		change(f)
		if rec := request("organization-admin", "POST", org, f); rec.Code != 400 {
			t.Fatal("ambiguous approval accepted", rec.Code)
		}
	}
	f := packageForm()
	f.Set("csrf", "wrong")
	if rec := request("organization-admin", "POST", org, f); rec.Code != 403 {
		t.Fatal("approval CSRF bypass", rec.Code)
	}
	if rec := request("organization-admin", "POST", org+"?single_app=yes", packageForm()); rec.Code != 400 {
		t.Fatal("query parameters altered approval", rec.Code)
	}
	rec := request("organization-admin", "POST", org, packageForm())
	if rec.Code != 303 {
		t.Fatal("approval failed", rec.Code, rec.Body.String())
	}
	version := strings.TrimPrefix(rec.Header().Get("Location"), org+"/")
	if _, err := uuid.Parse(version); err != nil {
		t.Fatal("approval redirect missing revision", err)
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		rec = request(user, "GET", scoped+"/software/catalog/"+version, nil)
		if rec.Code != 200 {
			t.Fatal("catalog read failed", user, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "route-download-secret") {
			t.Fatal("catalog read exposed source credentials")
		}
		if strings.Contains(rec.Body.String(), "Withdraw approval") {
			t.Fatal("scoped reader sees organization mutation")
		}
		if !strings.Contains(rec.Body.String(), "Route &lt;Editor&gt;") {
			t.Fatal("catalog did not escape approved display text")
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("catalog cache policy was weakened", rec.Header().Get("Cache-Control"))
		}
		if user == "scoped-viewer" && strings.Contains(rec.Body.String(), "Request installation") {
			t.Fatal("viewer sees installation form")
		}
	}

	for _, search := range []struct {
		query    string
		eligible bool
	}{{"Application route", true}, {"%", false}, {"No matching Mac", false}} {
		rec = request("scoped-operator", "GET", scoped+"/software/catalog/"+version+"?q="+url.QueryEscape(search.query), nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "Request installation") != search.eligible {
			t.Fatal("device search changed scope or interpreted wildcard input", search.query, rec.Code)
		}
	}
	install := scoped + "/software/catalog/" + version + "/install"
	installForm := func() url.Values { return url.Values{"device": {device}, "confirmed": {"yes"}} }
	if rec = request("scoped-viewer", "POST", install, installForm()); rec.Code != 403 {
		t.Fatal("viewer installed software", rec.Code)
	}
	f = installForm()
	f.Set("source_url", "https://example.test/unapproved.pkg")
	if rec = request("scoped-operator", "POST", install, f); rec.Code != 400 {
		t.Fatal("operator replaced approved source", rec.Code)
	}
	f = installForm()
	f.Del("confirmed")
	if rec = request("scoped-operator", "POST", install, f); rec.Code != 400 {
		t.Fatal("unconfirmed install accepted", rec.Code)
	}
	foreign := fmt.Sprintf("/tenant/%d/site/%d/software/catalog/%s/install", tenant, sibling, version)
	if rec = request("organization-admin", "POST", foreign, installForm()); rec.Code != 404 {
		t.Fatal("cross-site install accepted", rec.Code)
	}
	if rec = request("scoped-operator", "POST", install, installForm()); rec.Code != 303 {
		t.Fatal("scoped operator could not install approved software", rec.Code, rec.Body.String())
	}
	if rec = request("scoped-operator", "POST", install, installForm()); rec.Code != 409 {
		t.Fatal("duplicate active install accepted", rec.Code)
	}
	var assignment string
	if err := h.Model.DB.QueryRowContext(ctx, `SELECT id FROM mdm_apple_app_assignments WHERE device_id=$1`, device).Scan(&assignment); err != nil {
		t.Fatal(err)
	}
	page := scoped + "/ios/" + device + "/applications"
	if rec = request("scoped-viewer", "GET", page, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "Cancel queued operation") {
		t.Fatal("viewer application inventory invalid", rec.Code)
	}
	action := page + "/" + assignment + "/action"
	for _, operation := range []string{"cancel", "refresh", "remove"} {
		if rec = request("scoped-viewer", "POST", action, url.Values{"operation": {operation}, "confirmed": {"yes"}}); rec.Code != 403 {
			t.Fatal("viewer changed application", operation, rec.Code)
		}
	}
	exec(`UPDATE mdm_apple_devices SET inventory_at=clock_timestamp()-interval '2 days' WHERE id=$1`, device)
	if rec = request("scoped-operator", "POST", action, url.Values{"operation": {"cancel"}, "confirmed": {"yes"}}); rec.Code != 303 {
		t.Fatal("stale inventory prevented cancellation", rec.Code, rec.Body.String())
	}
	history := page + "/" + assignment + "/history"
	if rec = request("scoped-viewer", "GET", history, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Cancelled before confirmed execution") || strings.Contains(rec.Body.String(), "route-download-secret") {
		t.Fatal("read-only history missing or exposed source", rec.Code)
	}
	foreign = fmt.Sprintf("/tenant/%d/site/%d/ios/%s/applications/%s/history", tenant, sibling, device, assignment)
	if rec = request("organization-admin", "GET", foreign, nil); rec.Code != 404 {
		t.Fatal("history crossed device scope", rec.Code)
	}
	if rec = request("scoped-operator", "POST", scoped+"/software/catalog/"+version+"/withdraw", url.Values{"confirmed": {"yes"}}); rec.Code != 403 {
		t.Fatal("operator withdrew organization approval", rec.Code)
	}
	if rec = request("organization-admin", "POST", org+"/"+version+"/withdraw", url.Values{"confirmed": {"yes"}}); rec.Code != 303 {
		t.Fatal("withdrawal failed", rec.Code)
	}
	if rec = request("scoped-operator", "GET", scoped+"/software/catalog/"+version, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "Request installation") || !strings.Contains(rec.Body.String(), "Withdrawn at") {
		t.Fatal("withdrawn revision still offers install", rec.Code)
	}
}
