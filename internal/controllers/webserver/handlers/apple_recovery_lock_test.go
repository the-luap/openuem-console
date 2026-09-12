package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestRecoveryLockRoutesRequireDedicatedCapabilities(t *testing.T) {
	for path, want := range map[string]access.Capability{
		"/ios/:id/mac-admin":                           access.ManageDeviceSecurity,
		"/ios/:id/mac-admin/passwords/:key/reveal":     access.RetrieveRecoveryKeys,
		"/ios/:id/recovery-lock":                       access.ManageDeviceSecurity,
		"/ios/:id/recovery-lock/passwords/:key/reveal": access.RetrieveRecoveryKeys,
	} {
		for _, prefix := range []string{"", "/tenant/:tenant", "/tenant/:tenant/site/:site"} {
			if got, ok := appleCapability("POST", prefix+path); !ok || got != want {
				t.Fatal("wrong Recovery Lock capability", got, ok)
			}
			for _, method := range []string{"GET", "HEAD", "PUT", "DELETE"} {
				if _, ok := appleCapability(method, prefix+path); ok {
					t.Fatal("unexpected method authorized", method)
				}
			}
		}
	}
}

func exerciseAppleRecoveryLock(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	scope := apple.Scope{TenantID: tenant, SiteID: site}
	invite, err := h.Apple.InviteWithOptions(ctx, scope, "Recovery Lock console Mac", "organization-admin", apple.EnrollmentOptions{AllowMacDeviceLock: true}, h.Access)
	if err != nil {
		t.Fatal(err)
	}
	token := invite.URL[strings.LastIndex(invite.URL, "/")+1:]
	if err = h.Apple.ClaimEnrollment(ctx, token, strings.Repeat("A", 43), apple.PlatformMacOS); err != nil {
		t.Fatal(err)
	}
	// The native tests exercise SCEP and authenticated command delivery. This
	// fixture supplies readiness evidence for the real console authorization path.
	if _, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_devices SET status='enrolled',model='Mac16,1',os_version='15.0',inventory_at=clock_timestamp(),security_at=clock_timestamp(),apple_silicon=true,supervised=true,supervised_reported=true,security_inventory='{"ManagementStatus":{"UserApprovedEnrollment":true,"IsUserEnrollment":false}}',certificate_expires_at=clock_timestamp()+interval '1 year' WHERE id=$1`, invite.DeviceID); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/tenant/%d/site/%d/ios/%s", tenant, site, invite.DeviceID)
	path := base + "/recovery-lock"
	password := " synthetic-console-password <&日本語 "
	form := func() url.Values {
		return url.Values{"operation": {"import"}, "password": {password}, "confirm_recovery_lock": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", path, form()); rec.Code != 403 {
			t.Fatal("unprivileged password operation", user, rec.Code)
		}
	}
	for _, tc := range []struct {
		suffix string
		change func(url.Values)
		status int
	}{
		{"", func(f url.Values) { f.Set("csrf", "wrong") }, 403},
		{"", func(f url.Values) { f.Del("confirm_recovery_lock") }, 400},
		{"", func(f url.Values) { f.Set("confirm_recovery_lock", "no") }, 400},
		{"", func(f url.Values) { f.Add("confirm_recovery_lock", "yes") }, 400},
		{"", func(f url.Values) { f.Add("operation", "set") }, 400},
		{"", func(f url.Values) { f.Add("password", "duplicate") }, 400},
		{"", func(f url.Values) { f.Set("password", strings.Repeat("a", 1025)) }, 400},
		{"", func(f url.Values) { f.Set("password", "invalid\x00password") }, 400},
		{"?operation=import", func(f url.Values) {}, 400},
		{"?password=synthetic-query-password", func(f url.Values) {}, 400},
	} {
		f := form()
		tc.change(f)
		rec := request("organization-admin", "POST", path+tc.suffix, f)
		if rec.Code != tc.status || strings.Contains(rec.Body.String(), password) {
			t.Fatal("unsafe Recovery Lock form handling", rec.Code, tc.status)
		}
	}
	if rec := request("organization-admin", "POST", path, form()); rec.Code != 303 || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("authorized password import failed", rec.Code, rec.Body.String())
	}
	var key string
	if err = h.Model.DB.QueryRowContext(ctx, `SELECT id FROM mdm_apple_recovery_lock_keys WHERE device_id=$1`, invite.DeviceID).Scan(&key); err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"organization-admin", "scoped-viewer", "scoped-operator"} {
		rec := request(user, "GET", base, nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), password) || !strings.Contains(rec.Body.String(), "current Recovery Lock password state is not verified") {
			t.Fatal("unsafe Recovery Lock device page", user, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "Retrieve Recovery Lock password") != (user == "organization-admin") {
			t.Fatal("incorrect retrieval controls", user)
		}
		artifact("recovery-lock-"+user, rec)
	}
	reveal := path + "/passwords/" + key + "/reveal"
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", reveal, nil); rec.Code != 403 || strings.Contains(rec.Body.String(), password) {
			t.Fatal("unprivileged password disclosure", rec.Code)
		}
	}
	for _, method := range []string{"GET", "HEAD"} {
		if rec := request("organization-admin", method, reveal, nil); rec.Code == 200 || strings.Contains(rec.Body.String(), password) {
			t.Fatal("read method disclosed password")
		}
	}
	if rec := request("organization-admin", "POST", reveal, url.Values{"csrf": {"wrong"}}); rec.Code != 403 {
		t.Fatal("password disclosure ignored CSRF", rec.Code)
	}
	other := fmt.Sprintf("/tenant/%d/site/%d/ios/%s/recovery-lock/passwords/%s/reveal", tenant, sibling, invite.DeviceID, key)
	if rec := request("apple-console-admin", "POST", other, nil); rec.Code != 404 {
		t.Fatal("cross-site password disclosure", rec.Code)
	}
	rec := request("organization-admin", "POST", reveal, nil)
	if rec.Code != 200 || rec.Body.String() != password {
		t.Fatal("authorized password retrieval failed", rec.Code)
	}
	for header, part := range map[string]string{"Cache-Control": "no-store", "Pragma": "no-cache", "Content-Type": "text/plain", "Content-Security-Policy": "default-src 'none'", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"} {
		if !strings.Contains(rec.Header().Get(header), part) {
			t.Fatal("password response missing protection", header)
		}
	}
	var count int
	if err = h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_audit WHERE action='apple.recovery_lock.password.reveal' AND resource_id=$1 AND actor='organization-admin' AND details->>'site_id'=$2`, key, fmt.Sprint(site)).Scan(&count); err != nil || count != 1 {
		t.Fatal("password retrieval audit missing", count, err)
	}
	actor := "revoked-recovery-lock-admin"
	if _, err = h.Model.Client.User.Create().SetID(actor).SetName(actor).SetEmail(actor + "@example.test").SetUse2fa(false).SetRegister("users.completed").Save(ctx); err != nil {
		t.Fatal(err)
	}
	if err = h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 0, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: tenant}}}); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Access.Principal(ctx, actor); err != nil {
		t.Fatal(err)
	}
	if err = h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 1, nil); err != nil {
		t.Fatal(err)
	}
	if err = h.Apple.RequestRecoveryLock(ctx, scope, invite.DeviceID, "set", "", nil, actor, h.Access); err != access.ErrDenied {
		t.Fatal("revoked authority queued password change", err)
	}
	if plain, e := h.Apple.RevealRecoveryLockPassword(ctx, scope, invite.DeviceID, key, actor, h.Access); e != access.ErrDenied || len(plain) > 0 {
		t.Fatal("revoked authority disclosed password", e)
	}
}
