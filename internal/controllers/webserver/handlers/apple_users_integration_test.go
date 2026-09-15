package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func exerciseAppleUsers(t *testing.T, h *Handler, ctx context.Context, tenantID, siteID, siblingID int, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	scope := apple.Scope{TenantID: tenantID, SiteID: siteID}
	base := fmt.Sprintf("/tenant/%d/site/%d", tenantID, siteID)
	invite, err := h.Apple.Invite(ctx, scope, "Mac with managed users", "apple-console-admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_devices SET status='enrolled',udid=id::text,model='Mac16,1',os_version='15.0',per_user_connections=true,certificate_expires_at=clock_timestamp()+interval '1 year' WHERE id=$1`, invite.DeviceID); err != nil {
		t.Fatal(err)
	}
	userID := uuid.NewString()
	if _, err = h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_apple_users(id,tenant_id,site_id,device_id,user_id,short_name,long_name,status) VALUES($1,$2,$3,$4,$5,'alice','Alice Example','enrolled')`, userID, tenantID, siteID, invite.DeviceID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	path := base + "/ios/" + invite.DeviceID + "/users/" + userID
	for _, user := range []string{"apple-console-admin", "organization-admin", "scoped-operator", "scoped-viewer"} {
		rec := request(user, "GET", path, nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Alice Example") {
			t.Fatal("user page", user, rec.Code, rec.Body.String())
		}
		if user == "scoped-viewer" && strings.Contains(rec.Body.String(), "Apply to this user") {
			t.Fatal("viewer has assignment controls")
		}
	}
	for _, suffix := range []string{"/refresh", "/profiles", "/pause", "/resume", "/commands/" + uuid.NewString() + "/retry"} {
		if rec := request("scoped-viewer", "POST", path+suffix, nil); rec.Code != 403 {
			t.Fatal("viewer user mutation", suffix, rec.Code)
		}
	}
	if rec := request("scoped-operator", "POST", path+"/refresh", url.Values{"csrf": {"wrong"}}); rec.Code != 403 {
		t.Fatal("invalid user CSRF", rec.Code)
	}
	if rec := request("scoped-operator", "POST", path+"/refresh", nil); rec.Code != 303 {
		t.Fatal("user refresh", rec.Code, rec.Body.String())
	}
	commands, err := h.Apple.UserCommands(ctx, scope, invite.DeviceID, userID)
	if err != nil || len(commands) != 1 {
		t.Fatal(commands, err)
	}
	if _, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_user_commands SET status='failed',payload=''::bytea WHERE id=$1`, commands[0].ID); err != nil {
		t.Fatal(err)
	}
	if rec := request("scoped-operator", "POST", path+"/commands/"+commands[0].ID+"/retry", nil); rec.Code != 303 {
		t.Fatal("user retry", rec.Code, rec.Body.String())
	}
	if rec := request("scoped-operator", "POST", base+"/ios/"+invite.DeviceID+"/commands/"+commands[0].ID+"/retry", nil); rec.Code != 409 {
		t.Fatal("user command retried through device channel", rec.Code)
	}
	other := fmt.Sprintf("/tenant/%d/site/%d/ios/%s/users/%s", tenantID, siblingID, invite.DeviceID, userID)
	if rec := request("apple-console-admin", "GET", other, nil); rec.Code != 404 {
		t.Fatal("cross-site user read", rec.Code)
	}
	if rec := request("apple-console-admin", "POST", other+"/refresh", nil); rec.Code != 404 {
		t.Fatal("cross-site user refresh", rec.Code)
	}
	form := url.Values{"editor": {"wifi"}, "payload_scope": {"User"}, "name": {"User Wi-Fi"}, "identifier": {"eu.example.console.user"}, "ssid": {"UserNetwork"}, "wifi_security": {"WPA2"}, "wifi_password": {"private-user-password"}}
	if rec := request("organization-admin", "POST", base+"/ios/configurations", form); rec.Code != 303 {
		t.Fatal("create user profile", rec.Code, rec.Body.String())
	}
	profiles, err := h.Apple.Profiles(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	var profileID string
	for _, p := range profiles {
		if p.Identifier == "eu.example.console.user" {
			profileID = p.ID
			if p.Scope != "User" {
				t.Fatal("editor lost User scope")
			}
		}
	}
	if profileID == "" {
		t.Fatal("missing user profile")
	}
	if rec := request("scoped-operator", "POST", path+"/profiles", url.Values{"profile_id": {profileID}, "desired": {"installed"}}); rec.Code != 303 {
		t.Fatal("user assignment", rec.Code, rec.Body.String())
	}
	if rec := request("scoped-operator", "POST", base+"/ios/configurations/"+profileID+"/assign", url.Values{"expected_revision": {"1"}, "device_id": {invite.DeviceID}, "desired": {"installed"}}); rec.Code != 400 {
		t.Fatal("user profile entered device assignment", rec.Code)
	}
	rec := request("scoped-operator", "GET", path, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "User Wi-Fi") || strings.Contains(rec.Body.String(), "private-user-password") {
		t.Fatal("user detail rendering", rec.Code)
	}
	artifact("mac-user-console", rec)
	if rec := request("scoped-operator", "POST", path+"/pause", nil); rec.Code != 403 {
		t.Fatal("operator paused user without revoke capability", rec.Code)
	}
	if rec := request("organization-admin", "POST", path+"/pause", nil); rec.Code != 303 {
		t.Fatal("pause user", rec.Code, rec.Body.String())
	}
	artifact("mac-user-console-paused", request("organization-admin", "GET", path, nil))
	if rec := request("scoped-operator", "POST", path+"/resume", nil); rec.Code != 303 {
		t.Fatal("resume user", rec.Code, rec.Body.String())
	}
	u, err := h.Apple.User(ctx, scope, invite.DeviceID, userID)
	if err != nil || u.Status != "pending" {
		t.Fatal("resume skipped user enrollment", u, err)
	}
}
