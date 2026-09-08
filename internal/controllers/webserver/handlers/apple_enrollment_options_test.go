package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func exerciseAppleEnrollmentOptions(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	base := fmt.Sprintf("/tenant/%d/site/%d", tenant, site)
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin"} {
		rec := request(user, "GET", base+"/ios/setup", nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), `name="allow_mac_device_lock"`) != (user == "organization-admin") {
			t.Fatal("incorrect enrollment rights control", user, rec.Code)
		}
	}
	form := func() url.Values {
		return url.Values{"name": {"Mac lock invitation"}, "allow_mac_device_lock": {"yes"}}
	}
	count := func() int {
		t.Helper()
		var n int
		if err := h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_devices`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", base+"/ios/enroll", form()); rec.Code != 403 {
			t.Fatal("unprivileged lock invitation", user, rec.Code)
		}
	}
	for _, test := range []struct {
		path   string
		change func(url.Values)
		status int
	}{
		{base + "/ios/enroll", func(f url.Values) { f.Set("csrf", "wrong") }, 403},
		{base + "/ios/enroll", func(f url.Values) { f.Set("allow_mac_device_lock", "false") }, 400},
		{base + "/ios/enroll", func(f url.Values) { f.Set("allow_mac_device_lock", "") }, 400},
		{base + "/ios/enroll", func(f url.Values) { f.Add("allow_mac_device_lock", "no") }, 400},
		{base + "/ios/enroll", func(f url.Values) { f.Add("name", "Other Mac") }, 400},
		{base + "/ios/enroll", func(f url.Values) { f["site_id"] = []string{strconv.Itoa(site), strconv.Itoa(sibling)} }, 400},
		{base + "/ios/enroll?allow_mac_device_lock=yes", func(f url.Values) { f.Del("allow_mac_device_lock") }, 400},
		{base + "/ios/enroll", func(f url.Values) { f.Set("site_id", strconv.Itoa(sibling)) }, 403},
	} {
		f := form()
		test.change(f)
		if rec := request("organization-admin", "POST", test.path, f); rec.Code != test.status {
			t.Fatal("ambiguous enrollment option accepted", test.path, rec.Code, rec.Body.String())
		}
	}
	if count() != before {
		t.Fatal("rejected enrollment persisted")
	}
	for _, user := range []string{"scoped-operator", "organization-admin"} {
		f := form()
		if user == "scoped-operator" {
			f.Del("allow_mac_device_lock")
		}
		f.Set("name", "Enrollment options "+user)
		rec := request(user, "POST", base+"/ios/enroll", f)
		if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("authorized invitation failed", user, rec.Code, rec.Body.String())
		}
		var allowed bool
		var id string
		if err := h.Model.DB.QueryRowContext(ctx, `SELECT id,device_lock_allowed FROM mdm_apple_devices WHERE name=$1`, f.Get("name")).Scan(&id, &allowed); err != nil || allowed != (user == "organization-admin") {
			t.Fatal("invitation rights not preserved", err)
		}
		if allowed {
			var audited int
			if err := h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_audit WHERE resource_id=$1 AND actor=$2 AND action='apple.enrollment.device_lock.allow'`, id, user).Scan(&audited); err != nil || audited != 1 {
				t.Fatal("rights choice lacks audit", err)
			}
			if !strings.Contains(rec.Body.String(), "intended Mac") {
				t.Fatal("Mac-only invitation instructions missing")
			}
		}
	}
	// The public store entry point rechecks persisted grants instead of trusting
	// a principal previously loaded into the console session.
	actor := "revoked-enrollment-security"
	if _, err := h.Model.Client.User.Create().SetID(actor).SetName(actor).SetEmail(actor + "@example.test").SetUse2fa(false).Save(ctx); err != nil {
		t.Fatal(err)
	}
	grant := access.Grant{Role: access.TenantAdmin, Scope: access.Scope{TenantID: tenant}}
	if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 0, []access.Grant{grant}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Access.Principal(ctx, actor); err != nil {
		t.Fatal(err)
	}
	if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Apple.InviteWithOptions(ctx, apple.Scope{TenantID: tenant, SiteID: site}, "Revoked actor", actor, apple.EnrollmentOptions{AllowMacDeviceLock: true}, h.Access); err != access.ErrDenied {
		t.Fatal("revoked actor created invitation", err)
	}
	if count() != before+2 {
		t.Fatal("unexpected invitation after revocation")
	}
}
