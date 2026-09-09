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

func exerciseADEPlatformSSORoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	var profile, revision, version string
	if err := h.Model.DB.QueryRowContext(ctx, `SELECT id,revision_id FROM mdm_apple_profiles WHERE tenant_id=$1 AND identifier='com.example.console-unattended'`, tenant).Scan(&profile, &revision); err != nil {
		t.Fatal(err)
	}
	if err := h.Model.DB.QueryRowContext(ctx, `SELECT v.id FROM uem_software_versions v JOIN uem_software_packages p ON p.id=v.package_id AND p.tenant_id=v.tenant_id WHERE v.tenant_id=$1 AND p.identifier='com.example.RouteEditor' AND v.version='43.0' AND v.withdrawn_at IS NULL`, tenant).Scan(&version); err != nil {
		t.Fatal(err)
	}
	server, err := h.Apple.CreateADEServer(ctx, tenant, "SSO route fixture", "organization-admin", h.Access)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := h.Model.DB.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	policy, device, requirement := uuid.NewString(), uuid.NewString(), uuid.NewString()
	exec(`INSERT INTO mdm_apple_ade_profiles(id,tenant_id,server_id,site_id,platform,name,definition,selector_hash,public_url,removable,await_configuration,admin_options) VALUES($1,$2,$3,$4,'macos','SSO route policy','\x',$5,'https://mdm.example.test',false,true,'{"short_name":"localadmin","primary_account":"skip"}')`, policy, tenant, server, site, strings.Repeat("f", 64))
	exec(`INSERT INTO mdm_apple_ade_profile_apps(tenant_id,server_id,profile_id,package_id,version_id) SELECT $1,$2,$3,package_id,id FROM uem_software_versions WHERE tenant_id=$1 AND id=$4`, tenant, server, policy, version)
	exec(`INSERT INTO mdm_apple_ade_profile_sso(tenant_id,server_id,ade_profile_id,profile_id,profile_revision_id,package_id,application_version_id,approved_by,approval_reason) SELECT $1,$2,$3,$4,$5,package_id,id,'organization-admin','Review <provider>' FROM uem_software_versions WHERE tenant_id=$1 AND id=$6`, tenant, server, policy, profile, revision, version)
	exec(`INSERT INTO mdm_apple_ade_targets(tenant_id,server_id,serial,profile_id) VALUES($1,$2,'ROUTESSO1',$3)`, tenant, server, policy)
	exec(`INSERT INTO mdm_apple_devices(id,tenant_id,site_id,name,status,model,os_version,enrollment_method,enrollment_platform,invite_expires_at,certificate_expires_at,inventory_at,security_at,security_inventory) VALUES($1,$2,$3,'SSO route Mac','enrolled','Mac16,1','26.0','automated_device','macos',clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 year',clock_timestamp(),clock_timestamp(),'{"ManagementStatus":{"UserApprovedEnrollment":true}}')`, device, tenant, site)
	exec(`INSERT INTO mdm_apple_enrollment_layouts(device_id,tenant_id,profile_uuid,mdm_uuid,identity_uuid,identity_type,public_url,topic,access_rights) VALUES($1,$2,$3,$4,$5,'com.apple.security.scep','https://mdm.example.test','com.apple.mgmt.test',7955)`, device, tenant, uuid.NewString(), uuid.NewString(), uuid.NewString())
	exec(`INSERT INTO mdm_apple_ade_admissions(device_id,tenant_id,server_id,serial,generation,profile_id,expected_udid,signer_fingerprint,expires_at,awaiting_configuration,setup_state) VALUES($1,$2,$3,'ROUTESSO1',1,$4,'ROUTESSO-UDID',$5,clock_timestamp()+interval '1 hour',true,'awaiting')`, device, tenant, server, policy, strings.Repeat("e", 64))
	exec(`INSERT INTO mdm_apple_ade_device_sso(id,tenant_id,device_id,ade_profile_id,profile_id,profile_revision_id,package_id,application_version_id) SELECT $1,$2,$3,ade_profile_id,profile_id,profile_revision_id,package_id,application_version_id FROM mdm_apple_ade_profile_sso WHERE tenant_id=$2 AND ade_profile_id=$4`, requirement, tenant, device, policy)
	base := fmt.Sprintf("/tenant/%d/site/%d/ios/%s/setup/platform-sso", tenant, site, device)
	form := func() url.Values {
		return url.Values{"profile_revision": {revision}, "reason": {"Repair <profile> delivery"}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", base+"/repair", form()); rec.Code != 403 {
			t.Fatal("scoped role repaired organization requirement", user, rec.Code)
		}
	}
	for _, change := range []func(url.Values){func(f url.Values) { f.Del("confirmed") }, func(f url.Values) { f.Add("profile_revision", uuid.NewString()) }, func(f url.Values) { f.Set("unknown", "value") }} {
		f := form()
		change(f)
		if rec := request("organization-admin", "POST", base+"/repair", f); rec.Code != 400 {
			t.Fatal("ambiguous repair accepted", rec.Code)
		}
	}
	f := form()
	f.Set("csrf", "wrong")
	if rec := request("organization-admin", "POST", base+"/repair", f); rec.Code != 403 {
		t.Fatal("repair CSRF bypass", rec.Code)
	}
	if rec := request("organization-admin", "POST", base+"/repair?reason=query", form()); rec.Code != 400 {
		t.Fatal("query changed repair", rec.Code)
	}
	foreign := fmt.Sprintf("/tenant/%d/site/%d/ios/%s/setup/platform-sso", tenant, sibling, device)
	if rec := request("organization-admin", "POST", foreign+"/repair", form()); rec.Code != 404 {
		t.Fatal("repair crossed site", rec.Code)
	}
	f = form()
	f.Set("profile_revision", uuid.NewString())
	if rec := request("organization-admin", "POST", base+"/repair", f); rec.Code != 409 {
		t.Fatal("stale requirement accepted", rec.Code)
	}
	if rec := request("organization-admin", "POST", base+"/repair", form()); rec.Code != 303 {
		t.Fatal("reviewed repair failed", rec.Code, rec.Body.String())
	}
	for _, user := range []string{"organization-admin", "scoped-viewer"} {
		rec := request(user, "GET", base+"/repairs", nil)
		if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), "Repair &lt;profile&gt; delivery") || strings.Contains(rec.Body.String(), "synthetic-route-sso-token") {
			t.Fatal("repair history lost scope or exposed credentials", user, rec.Code)
		}
		rec = request(user, "GET", strings.TrimSuffix(base, "/setup/platform-sso"), nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Platform SSO setup requirement") || strings.Contains(rec.Body.String(), "synthetic-route-sso-token") || user == "scoped-viewer" && strings.Contains(rec.Body.String(), "Send retained profile revision") {
			t.Fatal("device provider panel lost role or privacy boundary", user, rec.Code)
		}
	}
	for _, path := range []string{foreign + "/repairs", base + "/repairs?before=" + uuid.NewString()} {
		if rec := request("organization-admin", "GET", path, nil); rec.Code != 404 {
			t.Fatal("repair history accepted foreign device or cursor", rec.Code)
		}
	}
	exec(`UPDATE mdm_apple_ade_admissions SET setup_state='complete',awaiting_configuration=false WHERE device_id=$1`, device)
	if rec := request("organization-admin", "POST", base+"/repair", form()); rec.Code != 409 {
		t.Fatal("repair reopened completed setup", rec.Code)
	}
}
