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

func exerciseAppleMacAdmin(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	// Native package tests exercise signed ADE, SCEP and device responses. This
	// fixture supplies only database readiness for the actual console routes.
	server, err := h.Apple.CreateADEServer(ctx, tenant, "Administrator route fixture", "organization-admin", h.Access)
	if err != nil {
		t.Fatal(err)
	}
	profile, device := uuid.NewString(), uuid.NewString()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := h.Model.DB.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	policy := `{"short_name":"localadmin","full_name":"Managed Admin","hidden":true,"primary_account":"standard","rotation_days":30}`
	exec(`INSERT INTO mdm_apple_ade_profiles(id,tenant_id,server_id,site_id,platform,name,definition,selector_hash,public_url,removable,await_configuration,admin_options) VALUES($1,$2,$3,$4,'macos','Synthetic account policy','\x', $5,'https://mdm.example.test',false,true,$6)`, profile, tenant, server, site, strings.Repeat("b", 64), policy)
	exec(`INSERT INTO mdm_apple_ade_targets(tenant_id,server_id,serial,profile_id) VALUES($1,$2,'ROUTEADMIN1',$3)`, tenant, server, profile)
	exec(`INSERT INTO mdm_apple_devices(id,tenant_id,site_id,name,status,model,os_version,enrollment_method,enrollment_platform,invite_expires_at,certificate_expires_at,supervised,supervised_reported,inventory_at) VALUES($1,$2,$3,'Route administrator Mac','enrolled','Mac14,7','15.6','automated_device','macos',clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 year',true,true,clock_timestamp())`, device, tenant, site)
	exec(`INSERT INTO mdm_apple_ade_admissions(device_id,tenant_id,server_id,serial,generation,profile_id,expected_udid,signer_fingerprint,expires_at,awaiting_configuration,setup_state) VALUES($1,$2,$3,'ROUTEADMIN1',1,$4,'ROUTE-UDID',$5,clock_timestamp()+interval '1 hour',true,'awaiting')`, device, tenant, server, profile, strings.Repeat("c", 64))
	exec(`INSERT INTO mdm_apple_mac_admin_accounts(device_id,tenant_id,options,creation_state) VALUES($1,$2,$3,'failed')`, device, tenant, policy)
	base := fmt.Sprintf("/tenant/%d/site/%d/ios/%s", tenant, site, device)
	form := func() url.Values { return url.Values{"operation": {"retry_creation"}, "confirmed": {"yes"}} }
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", base+"/mac-admin", form()); rec.Code != 403 {
			t.Fatal("unauthorized administrator action", rec.Code)
		}
	}
	for _, change := range []func(url.Values){func(f url.Values) { f.Del("confirmed") }, func(f url.Values) { f.Add("operation", "rotate") }, func(f url.Values) { f.Set("password", "forbidden-password-input") }} {
		f := form()
		change(f)
		if rec := request("organization-admin", "POST", base+"/mac-admin", f); rec.Code != 400 {
			t.Fatal("ambiguous action accepted", rec.Code)
		}
	}
	f := form()
	f.Set("csrf", "wrong")
	if rec := request("organization-admin", "POST", base+"/mac-admin", f); rec.Code != 403 {
		t.Fatal("CSRF bypass", rec.Code)
	}
	if rec := request("organization-admin", "POST", base+"/mac-admin?operation=rotate", form()); rec.Code != 400 {
		t.Fatal("query action accepted", rec.Code)
	}
	if rec := request("organization-admin", "POST", base+"/mac-admin", form()); rec.Code != 303 {
		t.Fatal("authorized account retry failed", rec.Code, rec.Body.String())
	}
	for _, operation := range []string{"pause_rotation", "resume_rotation"} {
		if rec := request("organization-admin", "POST", base+"/mac-admin", url.Values{"operation": {operation}, "confirmed": {"yes"}}); rec.Code != 303 {
			t.Fatal("schedule action failed", operation, rec.Code)
		}
	}
	var key, command string
	if err = h.Model.DB.QueryRowContext(ctx, `SELECT id,command_id FROM mdm_apple_mac_admin_keys WHERE device_id=$1`, device).Scan(&key, &command); err != nil {
		t.Fatal(err)
	}
	reveal := base + "/mac-admin/passwords/" + key + "/reveal"
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", reveal, url.Values{"confirmed": {"yes"}}); rec.Code != 403 {
			t.Fatal("unauthorized password disclosure", rec.Code)
		}
	}
	if rec := request("organization-admin", "POST", reveal, url.Values{}); rec.Code != 400 {
		t.Fatal("unconfirmed disclosure", rec.Code)
	}
	if rec := request("organization-admin", "GET", reveal, nil); rec.Code == 200 {
		t.Fatal("password retrievable through GET")
	}
	foreign := fmt.Sprintf("/tenant/%d/site/%d/ios/%s/mac-admin/passwords/%s/reveal", tenant, sibling, device, key)
	if rec := request("organization-admin", "POST", foreign, url.Values{"confirmed": {"yes"}}); rec.Code != 404 {
		t.Fatal("cross-site disclosure", rec.Code)
	}
	rec := request("organization-admin", "POST", reveal, url.Values{"confirmed": {"yes"}})
	if rec.Code != 200 || rec.Body.Len() != 43 || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("protected reveal failed", rec.Code)
	}
	password := rec.Body.String()
	page := request("organization-admin", "GET", base, nil)
	if page.Code != 200 || strings.Contains(page.Body.String(), password) || strings.Contains(page.Body.String(), command+"/retry") {
		t.Fatal("page leaked credentials or offered generic retry", page.Code)
	}
	var audited int
	if err = h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_audit WHERE tenant_id=$1 AND action='apple.mac_admin.password.reveal' AND resource_id=$2 AND (details->>'site_id')::bigint=$3 AND details->>'result'='success'`, tenant, key, site).Scan(&audited); err != nil || audited != 1 {
		t.Fatal("reveal was not audited once", audited, err)
	}
}
