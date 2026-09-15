package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func exerciseADEApplicationRoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, version string, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	org := fmt.Sprintf("/tenant/%d", tenant)
	search := org + "/ios/ade/software"
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "GET", search, nil); rec.Code != 403 {
			t.Fatal("application picker escaped organization permission", user, rec.Code)
		}
	}
	for _, query := range []struct {
		q     string
		found bool
	}{{"Route", true}, {"%", false}, {"_", false}, {"\\", false}, {"com.example.RouteEditor", true}} {
		rec := request("organization-admin", "GET", search+"?q="+url.QueryEscape(query.q), nil)
		var data struct {
			Items []struct{ ID, Package, Label string }
			Next  string
		}
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &data) != nil || (len(data.Items) > 0) != query.found {
			t.Fatal("approved application search failed", query.q, rec.Code)
		}
		if rec.Header().Get("Cache-Control") != "no-store" || strings.Contains(rec.Body.String(), "route-download-secret") {
			t.Fatal("picker leaked private source or cache policy")
		}
	}
	server, err := h.Apple.CreateADEServer(ctx, tenant, "Required app route fixture", "organization-admin", h.Access)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := h.Model.DB.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	profile, device, requirement := uuid.NewString(), uuid.NewString(), uuid.NewString()
	exec(`INSERT INTO mdm_apple_ade_profiles(id,tenant_id,server_id,site_id,platform,name,definition,selector_hash,public_url,removable,await_configuration) VALUES($1,$2,$3,$4,'macos','Required app route policy','\x',$5,'https://mdm.example.test',false,true)`, profile, tenant, server, site, strings.Repeat("d", 64))
	exec(`INSERT INTO mdm_apple_ade_profile_apps(tenant_id,server_id,profile_id,package_id,version_id) SELECT $1,$2,$3,package_id,id FROM uem_software_versions WHERE tenant_id=$1 AND id=$4`, tenant, server, profile, version)
	exec(`INSERT INTO mdm_apple_ade_targets(tenant_id,server_id,serial,profile_id) VALUES($1,$2,'ROUTEAPP1',$3)`, tenant, server, profile)
	exec(`INSERT INTO mdm_apple_devices(id,tenant_id,site_id,name,status,model,os_version,enrollment_method,enrollment_platform,invite_expires_at,certificate_expires_at,inventory_at) VALUES($1,$2,$3,'Required app route Mac','enrolled','Mac16,1','15.0','automated_device','macos',clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 year',clock_timestamp())`, device, tenant, site)
	exec(`INSERT INTO mdm_apple_enrollment_layouts(device_id,tenant_id,profile_uuid,mdm_uuid,identity_uuid,identity_type,public_url,topic,access_rights) VALUES($1,$2,$3,$4,$5,'com.apple.security.scep','https://mdm.example.test','com.apple.mgmt.test',7955)`, device, tenant, uuid.NewString(), uuid.NewString(), uuid.NewString())
	exec(`INSERT INTO mdm_apple_ade_admissions(device_id,tenant_id,server_id,serial,generation,profile_id,expected_udid,signer_fingerprint,expires_at,awaiting_configuration,setup_state) VALUES($1,$2,$3,'ROUTEAPP1',1,$4,'ROUTEAPP-UDID',$5,clock_timestamp()+interval '1 hour',true,'awaiting')`, device, tenant, server, profile, strings.Repeat("e", 64))
	exec(`INSERT INTO mdm_apple_ade_device_apps(id,tenant_id,device_id,profile_id,package_id,original_version_id,version_id) SELECT $1,$2,$3,$4,package_id,id,id FROM uem_software_versions WHERE tenant_id=$2 AND id=$5`, requirement, tenant, device, profile, version)
	f := url.Values{"name": {"Route correction"}, "identifier": {"com.example.RouteEditor"}, "version": {"43.0"}, "architecture": {"universal"}, "minimum_os": {"14.0"}, "sha256": {strings.Repeat("b", 64)}, "source_url": {"https://packages.example.test/corrected.pkg?secret=correction-secret"}, "confirmed": {"yes"}}
	rec := request("organization-admin", "POST", org+"/software/catalog", f)
	if rec.Code != 303 {
		t.Fatal("correction approval failed", rec.Code)
	}
	replacement := strings.TrimPrefix(rec.Header().Get("Location"), org+"/software/catalog/")
	base := fmt.Sprintf("%s/site/%d/ios/%s/setup/applications/%s", org, site, device, requirement)
	form := func() url.Values {
		return url.Values{"version": {replacement}, "reason": {"Correct <required> revision"}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec = request(user, "POST", base+"/replace", form()); rec.Code != 403 {
			t.Fatal("scoped role changed required application", user, rec.Code)
		}
	}
	for _, change := range []func(url.Values){func(f url.Values) { f.Del("confirmed") }, func(f url.Values) { f.Add("version", version) }, func(f url.Values) { f.Set("source_url", "https://example.test/unapproved.pkg") }} {
		f := form()
		change(f)
		if rec = request("organization-admin", "POST", base+"/replace", f); rec.Code != 400 {
			t.Fatal("ambiguous correction accepted", rec.Code)
		}
	}
	f = form()
	f.Set("csrf", "wrong")
	if rec = request("organization-admin", "POST", base+"/replace", f); rec.Code != 403 {
		t.Fatal("correction CSRF bypass", rec.Code)
	}
	if rec = request("organization-admin", "POST", base+"/replace?version="+version, form()); rec.Code != 400 {
		t.Fatal("query changed required revision", rec.Code)
	}
	foreign := fmt.Sprintf("%s/site/%d/ios/%s/setup/applications/%s", org, sibling, device, requirement)
	if rec = request("organization-admin", "POST", foreign+"/replace", form()); rec.Code != 404 {
		t.Fatal("correction crossed device site", rec.Code)
	}
	if rec = request("organization-admin", "POST", base+"/replace", form()); rec.Code != 303 {
		t.Fatal("authorized correction failed", rec.Code, rec.Body.String())
	}
	for _, user := range []string{"organization-admin", "scoped-viewer"} {
		rec = request(user, "GET", base+"/history", nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Correct &lt;required&gt; revision") || rec.Header().Get("Cache-Control") != "no-store" || strings.Contains(rec.Body.String(), "correction-secret") {
			t.Fatal("scoped correction history failed", user, rec.Code)
		}
	}
	if rec = request("organization-admin", "GET", foreign+"/history", nil); rec.Code != 404 {
		t.Fatal("history crossed device site", rec.Code)
	}
	if rec = request("organization-admin", "GET", base+"/history?before="+uuid.NewString(), nil); rec.Code != 404 {
		t.Fatal("foreign history cursor accepted", rec.Code)
	}
}
