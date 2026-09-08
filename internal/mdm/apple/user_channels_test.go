package apple

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"howett.net/plist"
)

func testUserEnroll(t *testing.T, s *Store, d *Device, name string) *UserChannel {
	t.Helper()
	userID := uuid.NewString()
	message := map[string]any{"MessageType": "UserAuthenticate", "UDID": d.UDID, "UserID": userID}
	response, err := s.UserCheckIn(t.Context(), d, message)
	if err != nil {
		t.Fatal(err)
	}
	var challenge map[string]any
	if _, err = plist.Unmarshal(response, &challenge); err != nil || challenge["DigestChallenge"] != "" {
		t.Fatal("unexpected user handshake", err, challenge)
	}
	message = map[string]any{"MessageType": "TokenUpdate", "UDID": d.UDID, "UserID": userID, "UserShortName": name, "UserLongName": "Test " + name, "NotOnConsole": false, "Topic": "com.apple.mgmt.test", "Token": []byte("token-" + name), "PushMagic": "magic-" + name}
	if _, err = s.UserCheckIn(t.Context(), d, message); err != nil {
		t.Fatal(err)
	}
	u, err := scanUser(s.db.QueryRow(`SELECT `+userColumns+` FROM mdm_apple_users WHERE device_id=$1 AND user_id=$2`, d.ID, userID))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func userReply(d *Device, u *UserChannel, status, id string) map[string]any {
	m := map[string]any{"UDID": d.UDID, "UserID": u.UserID, "Status": status}
	if id != "" {
		m["CommandUUID"] = id
	}
	return m
}

func userCommand(t *testing.T, s *Store, d *Device, u *UserChannel, message map[string]any) (string, string) {
	t.Helper()
	data, err := s.UserConnect(t.Context(), d, message)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		return "", ""
	}
	var envelope map[string]any
	if _, err = plist.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	return stringValue(envelope, "CommandUUID"), stringValue(envelope["Command"].(map[string]any), "RequestType")
}

func userProfileData(t *testing.T, kind string, settings map[string]any) []byte {
	t.Helper()
	p := map[string]any{"PayloadType": kind, "PayloadVersion": 1, "PayloadUUID": uuid.NewString(), "PayloadIdentifier": "test.user.settings"}
	for key, value := range settings {
		p[key] = value
	}
	data, err := plist.Marshal(map[string]any{"PayloadType": "Configuration", "PayloadScope": "User", "PayloadIdentifier": "test.user", "PayloadVersion": 1, "PayloadUUID": uuid.NewString(), "PayloadContent": []any{p}}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestUserProfileCapabilities(t *testing.T) {
	for _, kind := range []string{"com.apple.ManagedClient.preferences", "com.apple.wifi.managed", "com.apple.mail.managed"} {
		data := userProfileData(t, kind, nil)
		p, err := ParseProfile(data)
		if err != nil || p.Scope != "User" {
			t.Fatal(kind, p, err)
		}
		var root map[string]any
		plist.Unmarshal(p.Payload, &root)
		if root["PayloadScope"] != "User" {
			t.Fatal("user scope rewritten")
		}
		if err = validateUserProfile(p, &Device{Model: "Mac16,1", OSVersion: "15.0", PerUserConnections: true}); err != nil {
			t.Fatal(kind, err)
		}
	}
	for _, kind := range []string{"com.apple.TCC.configuration-profile-policy", "com.apple.MCX.FileVault2", "com.example.unknown"} {
		if _, err := ParseProfile(userProfileData(t, kind, nil)); err == nil {
			t.Fatal("unsupported user payload", kind)
		}
	}
	if _, err := ParseProfile(userProfileData(t, "com.apple.MCX", map[string]any{"DestroyFVKeyOnStandby": true})); err == nil {
		t.Fatal("device MCX settings accepted on user channel")
	}
	if _, err := ParseProfile(userProfileData(t, "com.apple.MCX", map[string]any{"com.apple.MCX.TimeServer": map[string]any{}})); err == nil {
		t.Fatal("time server accepted on user channel")
	}
	if len(profileCapabilities.MacOS) < 50 || len(profileCapabilities.Revision) != 40 {
		t.Fatal("missing capability provenance")
	}
	p, err := ParseProfile(userProfileData(t, "com.apple.MCX", map[string]any{"com.apple.cachedaccounts.CreateAtLogin": true}))
	if err != nil {
		t.Fatal("valid mobile-account user payload rejected", err)
	}
	if err = validateUserProfile(p, &Device{Model: "Mac16,1", OSVersion: "10.6", PerUserConnections: true}); err == nil {
		t.Fatal("user payload accepted on unsupported OS")
	}
}

func testUserToken(t *testing.T, s *Store, d *Device, u *UserChannel, token string, notOnConsole bool) {
	t.Helper()
	_, err := s.UserCheckIn(t.Context(), d, map[string]any{"MessageType": "TokenUpdate", "UDID": d.UDID, "UserID": u.UserID, "UserShortName": u.ShortName, "UserLongName": u.LongName, "NotOnConsole": notOnConsole, "Topic": "com.apple.mgmt.test", "Token": []byte(token), "PushMagic": "magic-" + token})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMacUserPauseExpiryAndPushLeases(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Lifecycle", "Mac16,1", "15.0")
	u := testUserEnroll(t, s, d, "alice")
	p, err := s.SaveProfile(t.Context(), 1, "", 0, userProfileData(t, "com.apple.ManagedClient.preferences", nil), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignUserProfile(t.Context(), scope, d.ID, u.ID, p.ID, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	lease, err := s.leaseUserPush(t.Context())
	if err != nil || lease == nil || lease.id != u.ID {
		t.Fatal("user push lease", lease, err)
	}
	if next, err := s.leaseUserPush(t.Context()); err != nil || next != nil {
		t.Fatal("duplicate push lease", next, err)
	}
	testUserToken(t, s, d, u, "rotated-token", true)
	if err = s.recordUserPushOutcome(t.Context(), lease, "invalid_token", "Old token response"); err != nil {
		t.Fatal(err)
	}
	current, _ := s.User(t.Context(), scope, d.ID, u.ID)
	if current.PushStatus != "pending" {
		t.Fatal("late push outcome replaced rotated token", current)
	}
	if next, err := s.leaseUserPush(t.Context()); err != nil || next != nil {
		t.Fatal("offline user was pushed", next, err)
	}
	if data, err := s.UserConnect(t.Context(), d, userReply(d, u, "Idle", "")); err != nil || len(data) != 0 {
		t.Fatal("offline user received work", err)
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_user_commands SET expires_at=clock_timestamp()-interval '1 second' WHERE user_channel_id=$1 AND request_type='InstallProfile'`, u.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.MaintainUserChannels(t.Context()); err != nil {
		t.Fatal(err)
	}
	assignments, _ := s.UserAssignments(t.Context(), scope, d.ID, u.ID)
	if len(assignments) != 1 || assignments[0].Status != "failed" {
		t.Fatal("expiry not reconciled", assignments)
	}
	var commandID string
	if err = s.db.QueryRow(`SELECT command_id FROM mdm_apple_user_assignments WHERE user_channel_id=$1`, u.ID).Scan(&commandID); err != nil {
		t.Fatal(err)
	}
	if err = s.RetryUserCommand(t.Context(), scope, d.ID, u.ID, commandID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = s.RetryUserCommand(t.Context(), scope, d.ID, u.ID, commandID, "admin"); err == nil {
		t.Fatal("superseded retry accepted")
	}
	if err = s.PauseUserManagement(t.Context(), scope, d.ID, u.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.UserConnect(t.Context(), d, userReply(d, u, "Idle", "")); !errors.Is(err, ErrUserChannelDeclined) {
		t.Fatal("paused user delivered commands", err)
	}
	if err = s.DeleteProfile(t.Context(), 1, p.ID, "admin"); err == nil {
		t.Fatal("pause implied profile removal")
	}
	p, err = s.SaveProfile(t.Context(), 1, p.ID, 1, userProfileData(t, "com.apple.ManagedClient.preferences", nil), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ResumeUserManagement(t.Context(), scope, d.ID, u.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.UserConnect(t.Context(), d, userReply(d, u, "Idle", "")); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("resumed user did not require a new token", err)
	}
	assignments, _ = s.UserAssignments(t.Context(), scope, d.ID, u.ID)
	if assignments[0].Revision != p.Revision || assignments[0].Status != "pending" {
		t.Fatal("resume did not use current revision", assignments)
	}
	testUserToken(t, s, d, u, "after-login", false)
	if _, kind := userCommand(t, s, d, u, userReply(d, u, "Idle", "")); kind != "InstallProfile" {
		t.Fatal(kind)
	}
	if err = s.RevokeEnrollment(t.Context(), scope, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	current, _ = s.User(t.Context(), scope, d.ID, u.ID)
	if current.Status != "not_managed" {
		t.Fatal("native revocation kept user managed")
	}
	var secrets bool
	if err = s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM mdm_apple_users WHERE device_id=$1 AND push_token IS NOT NULL) OR EXISTS(SELECT 1 FROM mdm_apple_user_commands WHERE device_id=$1 AND status IN ('queued','sent','not_now'))`, d.ID).Scan(&secrets); err != nil || secrets {
		t.Fatal("revocation retained user work or credentials", err)
	}
}

func TestMacUserIdentityTokensWaitForDeviceConfirmation(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Renewal users", "Mac16,1", "15.0")
	u := testUserEnroll(t, s, d, "alice")
	drainMacInventory(t, s, d)
	testIdentityDue(t, s, d)
	lease, err := s.leaseUserPush(t.Context())
	if err != nil || lease == nil {
		t.Fatal(err)
	}
	if err = s.ScheduleIdentityRenewals(t.Context()); err != nil {
		t.Fatal(err)
	}
	renewal := testIdentityGeneration(t, s, d)
	profile := testIdentityDelivery(t, s, d, renewal)
	var root map[string]any
	plist.Unmarshal(profile, &root)
	capability := false
	for _, item := range root["PayloadContent"].([]any) {
		p := item.(map[string]any)
		if p["PayloadType"] == "com.apple.mdm" {
			for _, c := range p["ServerCapabilities"].([]any) {
				capability = capability || c == "com.apple.mdm.per-user-connections"
			}
		}
	}
	if !capability {
		t.Fatal("renewal removed immutable per-user capability")
	}
	a, err := s.scepRenewalAuthority(t.Context(), d.ID, renewal.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	f, csr := testSCEPDeviceRequest(t, d.ID, testSCEPProfile(t, profile)["Challenge"].(string), a.ca, a.ra)
	request, err := parseSCEPRequest(testSCEPWire(t, f, csr, scepWireOptions{}), a.ra, a.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := testIdentityIssue(t, s, a, f, request)
	testUserToken(t, s, candidate, u, "candidate-user-token", false)
	if response, err := s.UserConnect(t.Context(), candidate, userReply(d, u, "Idle", "")); err != nil || len(response) != 0 {
		t.Fatal("candidate user processed work", err)
	}
	readToken := func() string {
		t.Helper()
		var encrypted []byte
		if err := s.db.QueryRow(`SELECT push_token FROM mdm_apple_users WHERE id=$1`, u.ID).Scan(&encrypted); err != nil {
			t.Fatal(err)
		}
		plain, err := s.secrets.open(encrypted, secretPurpose(1, u.ID, "user_push_token"))
		if err != nil {
			t.Fatal(err)
		}
		return string(plain)
	}
	if readToken() != "token-alice" {
		t.Fatal("candidate user replaced active credentials")
	}
	testIdentityToken(t, s, candidate)
	if _, err = s.Connect(t.Context(), candidate, map[string]any{"UDID": d.UDID, "Status": "Idle"}); err != nil {
		t.Fatal(err)
	}
	if readToken() != "candidate-user-token" {
		t.Fatal("device confirmation did not promote user token")
	}
	if _, err = s.UserConnect(t.Context(), d, userReply(d, u, "Idle", "")); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("retired identity used user channel", err)
	}
	if err = s.recordUserPushOutcome(t.Context(), lease, "invalid_token", "Old token"); err != nil {
		t.Fatal(err)
	}
	current, _ := s.User(t.Context(), scope, d.ID, u.ID)
	if current.PushStatus != "pending" {
		t.Fatal("old push outcome survived promotion")
	}
	var staged int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_user_renewal_tokens WHERE device_id=$1`, d.ID).Scan(&staged); err != nil || staged != 0 {
		t.Fatal("staged credentials retained", err)
	}
}

func TestMacUserCommandsStayWithinTheirChannel(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	d, cert, _ := testEnrollPlatformWithKey(t, s, Scope{TenantID: 1, SiteID: 1}, "Users", "Mac16,1", "15.0")
	if !d.PerUserConnections || !d.Capabilities().UserChannel {
		t.Fatal("new Mac has no user channel")
	}
	a, b := testUserEnroll(t, s, d, "alice"), testUserEnroll(t, s, d, "bob")
	id, kind := userCommand(t, s, d, a, userReply(d, a, "Idle", ""))
	if kind != "ProfileList" {
		t.Fatal(kind)
	}
	if _, err := s.UserConnect(t.Context(), d, userReply(d, b, "Acknowledged", id)); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("cross-user receipt", err)
	}
	if _, err := s.Connect(t.Context(), d, userReply(d, a, "Acknowledged", id)); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("user receipt entered device channel", err)
	}
	if data, err := s.UserConnect(t.Context(), d, userReply(d, a, "NotNow", id)); err != nil || len(data) != 0 {
		t.Fatal("NotNow blocked login", err)
	}
	if _, err := s.Users(t.Context(), Scope{TenantID: 2}, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant users", err)
	}
	if _, err := s.User(t.Context(), Scope{TenantID: 1, SiteID: 2}, d.ID, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-site user", err)
	}
	var encrypted []byte
	if err := s.db.QueryRow(`SELECT push_token FROM mdm_apple_users WHERE id=$1`, a.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("token-alice")) {
		t.Fatal("unencrypted user push token")
	}
	if _, err := s.secrets.open(encrypted, secretPurpose(1, b.ID, "user_push_token")); err == nil {
		t.Fatal("user token not cryptographically bound")
	}
	public, _ := json.Marshal(a)
	if bytes.Contains(public, []byte("token-alice")) || bytes.Contains(public, []byte("magic-alice")) {
		t.Fatal("user secret in public read model")
	}
	request := func(path string, message map[string]any) *httptest.ResponseRecorder {
		body, _ := plist.Marshal(message, plist.XMLFormat)
		r := httptest.NewRequest("PUT", "https://mdm.example.test/mdm/apple/"+d.ID+"/"+path, bytes.NewReader(body))
		r.TLS = &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{cert}}
		rec := httptest.NewRecorder()
		s.ProtocolHandler(nil).ServeHTTP(rec, r)
		return rec
	}
	if rec := request("checkin", map[string]any{"MessageType": "UserAuthenticate", "UDID": d.UDID, "UserID": uuid.NewString()}); rec.Code != 200 || !strings.Contains(rec.Body.String(), "DigestChallenge") {
		t.Fatal("user HTTP dispatch", rec.Code, rec.Body.String())
	}
	if rec := request("checkin", map[string]any{"MessageType": "GetBootstrapToken", "UDID": d.UDID, "UserID": a.UserID}); rec.Code != 401 {
		t.Fatal("user accessed bootstrap token", rec.Code)
	}
	if rec := request("connect", map[string]any{"Status": "Idle", "UDID": d.UDID, "UserID": "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"}); rec.Code != 200 || !strings.Contains(rec.Body.String(), "CommandUUID") {
		t.Fatal("Mac device marker dispatch", rec.Code, rec.Body.String())
	}
	if _, err := s.db.Exec(`UPDATE mdm_apple_devices SET per_user_connections=false WHERE id=$1`, d.ID); err != nil {
		t.Fatal(err)
	}
	if rec := request("checkin", map[string]any{"MessageType": "UserAuthenticate", "UDID": d.UDID, "UserID": uuid.NewString()}); rec.Code != 410 {
		t.Fatal("legacy enrollment gained user channel", rec.Code)
	}
}

func TestMacUserProfileRevisionAndLateResponses(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Profiles", "Mac16,1", "15.0")
	u := testUserEnroll(t, s, d, "alice")
	oldList, _ := userCommand(t, s, d, u, userReply(d, u, "Idle", ""))
	p, err := s.SaveProfile(t.Context(), 1, "", 0, userProfileData(t, "com.apple.ManagedClient.preferences", map[string]any{"PayloadContent": map[string]any{"com.example.app": map[string]any{"Forced": []any{map[string]any{"mcx_preference_settings": map[string]any{"Secret": "profile-secret"}}}}}}), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID}, "installed", "admin"); err == nil {
		t.Fatal("User profile entered device queue")
	}
	if err = s.AssignUserProfile(t.Context(), scope, d.ID, u.ID, p.ID, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	install, kind := userCommand(t, s, d, u, userReply(d, u, "Idle", ""))
	if kind != "InstallProfile" {
		t.Fatal(kind)
	}
	list, kind := userCommand(t, s, d, u, userReply(d, u, "Acknowledged", install))
	if kind != "ProfileList" || list == oldList {
		t.Fatal("stale profile inventory used", list, kind)
	}
	ack := userReply(d, u, "Acknowledged", list)
	ack["ProfileList"] = []any{map[string]any{"PayloadIdentifier": p.Identifier, "PayloadUUID": strings.ToUpper(p.UUID), "IsManaged": true}}
	userCommand(t, s, d, u, ack)
	assignments, err := s.UserAssignments(t.Context(), scope, d.ID, u.ID)
	if err != nil || len(assignments) != 1 || assignments[0].Status != "verified" {
		t.Fatal(assignments, err)
	}
	if err = s.DeleteProfile(t.Context(), 1, p.ID, "admin"); err == nil {
		t.Fatal("deleted installed user profile")
	}
	if err = s.AssignUserProfile(t.Context(), scope, d.ID, u.ID, p.ID, "removed", "admin"); err != nil {
		t.Fatal(err)
	}
	remove, kind := userCommand(t, s, d, u, userReply(d, u, "Idle", ""))
	if kind != "RemoveProfile" {
		t.Fatal(kind)
	}
	stale := userReply(d, u, "Acknowledged", oldList)
	stale["ProfileList"] = []any{}
	userCommand(t, s, d, u, stale)
	assignments, _ = s.UserAssignments(t.Context(), scope, d.ID, u.ID)
	if assignments[0].Status != "pending" {
		t.Fatal("stale inventory verified removal", assignments)
	}
	list, kind = userCommand(t, s, d, u, userReply(d, u, "Acknowledged", remove))
	if kind != "ProfileList" {
		t.Fatal(kind)
	}
	ack = userReply(d, u, "Acknowledged", list)
	ack["ProfileList"] = []any{}
	userCommand(t, s, d, u, ack)
	assignments, _ = s.UserAssignments(t.Context(), scope, d.ID, u.ID)
	if assignments[0].Status != "verified" {
		t.Fatal(assignments)
	}
	if err = s.DeleteProfile(t.Context(), 1, p.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = s.MaintainUserChannels(t.Context()); err != nil {
		t.Fatal(err)
	}
}
