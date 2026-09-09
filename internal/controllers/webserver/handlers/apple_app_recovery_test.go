package handlers

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func exerciseAppleAppRecovery(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, device, version string, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := h.Model.DB.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	old, assignment, attempt, udid := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	exec(`UPDATE mdm_apple_devices SET udid=$2,inventory_at=clock_timestamp() WHERE id=$1`, device, udid)
	exec(`INSERT INTO mdm_apple_devices(id,tenant_id,site_id,name,status,udid,model,os_version,enrollment_method,enrollment_platform,certificate_expires_at,invite_expires_at) VALUES($1,$2,$3,'Private earlier <Site>','unenrolled',upper($4),'Mac16,1','15.0','manual_device','macos',clock_timestamp()+interval '1 year',clock_timestamp())`, old, tenant, sibling, udid)
	exec(`INSERT INTO mdm_apple_app_assignments(id,tenant_id,device_id,package_id,version_id,desired,status) SELECT $1,tenant_id,$2,package_id,id,'present','not_managed' FROM uem_software_versions WHERE id=$3`, assignment, old, version)
	exec(`INSERT INTO mdm_apple_app_attempts(id,tenant_id,device_id,package_id,assignment_id,version_id,operation,options,status,requested_by,dispatched_at) SELECT $1,tenant_id,device_id,package_id,id,version_id,'install','{}','uncertain','private-actor',clock_timestamp() FROM mdm_apple_app_assignments WHERE id=$2`, attempt, assignment)
	base := fmt.Sprintf("/tenant/%d/site/%d/ios/%s/applications", tenant, site, device)
	page := base + "/previous"
	action := page + "/" + attempt + "/resolve"
	form := func() url.Values {
		return url.Values{"evidence": {"installer_stopped"}, "reason": {"Synthetic observed <stopping evidence>"}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		for _, method := range []string{"GET", "POST"} {
			path, f := page, url.Values(nil)
			if method == "POST" {
				path, f = action, form()
			}
			if rec := request(user, method, path, f); rec.Code != 403 {
				t.Fatal("scoped role reviewed or cleared another site's operation", user, method, rec.Code)
			}
		}
		rec := request(user, "GET", base, nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "An earlier enrollment") {
			t.Fatal("reader missing generic risk", rec.Code)
		}
		for _, secret := range []string{old, attempt, "Private earlier", "private-actor", "Review previous enrollments"} {
			if strings.Contains(rec.Body.String(), secret) {
				t.Fatal("generic risk disclosed earlier enrollment", secret)
			}
		}
	}
	rec := request("organization-admin", "GET", page, nil)
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), "Private earlier &lt;Site&gt;") || !strings.Contains(rec.Body.String(), "Record stopping evidence") || strings.Contains(rec.Body.String(), "route-download-secret") {
		t.Fatal("organization recovery page failed privacy or rendering", rec.Code)
	}
	foreign := fmt.Sprintf("/tenant/%d/site/%d/ios/%s/applications/previous", tenant, sibling, device)
	if rec = request("organization-admin", "GET", foreign, nil); rec.Code != 404 {
		t.Fatal("recovery page crossed target scope", rec.Code)
	}
	for _, change := range []func(url.Values){func(f url.Values) { f.Del("confirmed") }, func(f url.Values) { f.Add("reason", "other") }, func(f url.Values) { f.Set("evidence", "rebooted") }, func(f url.Values) { f.Set("reason", "") }, func(f url.Values) { f.Set("reason", strings.Repeat("x", 1001)) }, func(f url.Values) { f.Set("previous_device", old) }} {
		f := form()
		change(f)
		if rec = request("organization-admin", "POST", action, f); rec.Code != 400 {
			t.Fatal("invalid stopping evidence accepted", rec.Code)
		}
	}
	f := form()
	f.Set("csrf", "wrong")
	if rec = request("organization-admin", "POST", action, f); rec.Code != 403 {
		t.Fatal("evidence CSRF bypass", rec.Code)
	}
	if rec = request("organization-admin", "POST", action+"?evidence=device_erased", form()); rec.Code != 400 {
		t.Fatal("query changed evidence", rec.Code)
	}
	if rec = request("organization-admin", "POST", action, form()); rec.Code != 303 {
		t.Fatal("organization stopping evidence failed", rec.Code, rec.Body.String())
	}
	rec = request("organization-admin", "GET", page, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Stopping evidence recorded") || !strings.Contains(rec.Body.String(), "Synthetic observed &lt;stopping evidence&gt;") || strings.Contains(rec.Body.String(), `name="evidence"`) {
		t.Fatal("immutable receipt rendering incorrect", rec.Code)
	}
	if rec = request("organization-admin", "POST", action, form()); rec.Code != 404 {
		t.Fatal("receipt was recorded twice", rec.Code)
	}
	if rec = request("scoped-operator", "GET", base, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "An earlier enrollment") {
		t.Fatal("resolved generic risk persisted", rec.Code)
	}
}
