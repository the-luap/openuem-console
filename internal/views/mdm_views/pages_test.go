package mdm_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"
	"github.com/alexedwards/scs/v2"
	"github.com/invopop/ctxi18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestManagementPagesRenderSafeFormsAndInventory(t *testing.T) {
	if err := ctxi18n.LoadWithDefault(locales.Content, "en"); err != nil {
		t.Fatal(err)
	}
	ctx, err := ctxi18n.WithLocale(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	sm.Put(ctx, "uid", "preview-admin")
	sm.Put(ctx, "username", "Preview administrator")
	info := &partials.CommonInfo{Principal: access.Principal{UserID: "preview-admin", Grants: []access.Grant{{Role: access.Administrator}}}, SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "-1", ProfileSiteID: "1", CSRFToken: "test-csrf-token", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
	req := httptest.NewRequest("GET", "/tenant/1/devices", nil).WithContext(ctx)
	c := echo.New().NewContext(req, httptest.NewRecorder())
	now := time.Now().UTC()
	reminders := []apple.PushReminderSummary{{Fingerprint: strings.Repeat("d", 64), Stage: 7, CreatedAt: now, ExpiresAt: now.Add(6 * 24 * time.Hour), Pending: 2, Failed: 1, Sent: 1, NextAttemptAt: &now}, {Fingerprint: strings.Repeat("e", 64), Stage: 30, CreatedAt: now.Add(-24 * time.Hour), ExpiresAt: now.Add(6 * 24 * time.Hour), ResolvedAt: &now, Sent: 2, Cancelled: 1}}
	vendorExpires := now.Add(24 * time.Hour)
	d := &apple.Device{ID: "10000000-0000-0000-0000-000000000001", Name: "Sales iPhone", Model: "iPhone16,1", OSVersion: "18.6.2", BuildVersion: "22G100", SerialNumber: "EXAMPLE123", Supervised: true, Status: "enrolled", InventoryAt: &now, LastSeen: &now, AppsAt: &now, ProfilesAt: &now, CertificateExpiresAt: now.AddDate(1, 0, 0), PushStatus: "accepted", Apps: []apple.Application{{Identifier: "com.example.app", Name: "Example app", Version: "42", ShortVersion: "1.2"}}}
	p := apple.Profile{ID: "20000000-0000-0000-0000-000000000001", Name: "Company Wi-Fi", Identifier: "eu.example.wifi", Revision: 2, PayloadTypes: []string{"com.apple.wifi.managed"}}
	policy := &apple.UpdatePolicy{TargetVersion: "18.7.1", Deadline: "2026-10-01T18:00:00", Status: "waiting"}
	detail := Detail{Device: d, Profiles: []apple.Profile{p}, Assignments: []apple.Assignment{{ProfileID: p.ID, Name: p.Name, Revision: 2, Desired: "installed", Status: "verified"}}, Policy: policy, Compliance: "update_required", CatalogAt: &now, Releases: []apple.OSRelease{{Version: "18.7.1", Build: "22H100"}, {Version: "18.7.1", Build: "22H6100"}}}
	detail.IdentityRenewals = []apple.IdentityRenewal{{ID: "40000000-0000-0000-0000-000000000001", Status: "issued", CommandID: "50000000-0000-0000-0000-000000000001", PreviousFingerprint: strings.Repeat("1a", 32), Fingerprint: strings.Repeat("2b", 32), CreatedAt: now, CertificateExpiresAt: &vendorExpires, TokenUpdatedAt: &now}, {ID: "40000000-0000-0000-0000-000000000002", Status: "confirmed", CommandID: "50000000-0000-0000-0000-000000000002", PreviousFingerprint: strings.Repeat("3c", 32), Fingerprint: strings.Repeat("1a", 32), CreatedAt: now.AddDate(-1, 0, 0), ConfirmedAt: &now}}
	identityExpires := now.AddDate(1, 0, 0)
	d.CertificateExpiresAt = now.Add(20 * 24 * time.Hour)
	detail.IdentityRenewals[0].CertificateExpiresAt = &identityExpires
	detail.Commands = []apple.Command{{ID: detail.IdentityRenewals[0].CommandID, IdentityRenewal: true, RequestType: "InstallProfile", Status: "expired"}, {ID: "60000000-0000-0000-0000-000000000001", RequestType: "DeviceInformation", Status: "failed"}}
	mac := *d
	mac.Name, mac.Model, mac.OSVersion, mac.BuildVersion = "Design Mac", "Mac16,1", "15.0", "24A335"
	silicon := true
	mac.AppleSilicon, mac.SupervisedReported, mac.SecurityAt = &silicon, true, &now
	mac.SoftwareUpdateDeviceID = "J313AP"
	mac.SecurityInventory = map[string]any{"ManagementStatus": map[string]any{"UserApprovedEnrollment": true}, "BootstrapTokenAllowedForAuthentication": "allowed", "BootstrapTokenRequiredForSoftwareUpdate": true}
	macDetail := Detail{Device: &mac, CatalogAt: &now, Releases: []apple.OSRelease{{Version: "15.1", Build: "24B1"}}, Policy: &apple.UpdatePolicy{TargetVersion: "15.1", TargetBuild: "24B1", Deadline: "2026-10-01T18:00:00", Status: "unavailable"}}
	macDetail.MacBindingReady = true
	linked := macDetail
	linked.Mac = &apple.MacDevice{ID: "70000000-0000-4000-8000-000000000001", MDMID: mac.ID, AgentID: "80000000-0000-4000-8000-000000000001", MDMStatus: "enrolled", AgentStatus: "enrolled", AgentName: "Design agent", AgentSeen: &now, AgentExpiresAt: now.AddDate(1, 0, 0), History: []apple.MacChannelHistory{{Kind: "mdm", DeviceID: mac.ID, Status: "enrolled", AttachedAt: now}, {Kind: "agent", DeviceID: "80000000-0000-4000-8000-000000000001", Status: "enrolled", AttachedAt: now}, {Kind: "agent", DeviceID: "80000000-0000-4000-8000-000000000002", Status: "revoked", AttachedAt: now.AddDate(-1, 0, 0), RetiredAt: &now}}}
	linked.AgentURL = "/tenant/1/computers/" + linked.Mac.AgentID
	linked.MacBinding = &apple.MacBinding{Status: "consumed", ExpiresAt: now.Add(time.Hour), InstalledAt: &now, CompletedAt: &now, CleanupAt: &now}
	reader := *info
	reader.Principal = access.Principal{UserID: "preview-reader", Grants: []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: 1}}}}
	queued := macDetail
	queued.MacBinding = &apple.MacBinding{Status: "queued", ExpiresAt: now.Add(time.Hour)}
	conflict := macDetail
	conflict.MacBinding = &apple.MacBinding{Status: "conflict", ExpiresAt: now.Add(time.Hour), InstalledAt: &now, CompletedAt: &now, CleanupAttempts: 1, CleanupStatus: "failed"}
	cleanup := linked
	cleanup.MacBinding = &apple.MacBinding{Status: "consumed", ExpiresAt: now.Add(time.Hour), InstalledAt: &now, CompletedAt: &now, CleanupAttempts: 1, CleanupStatus: "queued"}
	cleanup.Commands = []apple.Command{{ID: "90000000-0000-4000-8000-000000000001", RequestType: "RemoveProfile", Status: "failed", MacBinding: true}}

	user := &apple.UserChannel{ID: "a0000000-0000-4000-8000-000000000001", DeviceID: mac.ID, UserID: "b0000000-0000-4000-8000-000000000001", ShortName: "alice", LongName: "Alice Example", Status: "enrolled", PushStatus: "accepted", LastSeen: now, ProfilesAt: &now, InstalledProfiles: []apple.InstalledProfile{{Identifier: "com.example.user", UUID: "c0000000-0000-4000-8000-000000000001", Name: "User preferences", Managed: true}}}
	userProfile := p
	userProfile.Scope = "User"
	userDetail := UserDetail{Device: &mac, User: user, Profiles: []apple.Profile{p, userProfile}, Assignments: []apple.Assignment{{ProfileID: p.ID, Name: "User preferences", Revision: 2, Desired: "installed", Status: "verified"}}, Commands: []apple.Command{{ID: "d0000000-0000-4000-8000-000000000001", RequestType: "ProfileList", Status: "failed", CreatedAt: now}}}
	pausedUser := *user
	pausedUser.Status = "blocked"
	pausedDetail := userDetail
	pausedDetail.User = &pausedUser
	mac.PerUserConnections = true
	macDetail.Users = []apple.UserChannel{*user}
	filevault := macDetail
	filevault.FileVault = &apple.FileVault{DeviceID: mac.ID, Desired: "enabled", Phase: "active", KeyID: "e0000000-0000-4000-8000-000000000001", EscrowedAt: &now, ValidationReady: true}
	filevault.FileVaultKeys = []apple.FileVaultKeyHistory{{ID: filevault.FileVault.KeyID, Current: true, CreatedAt: now, ObservedAt: now}}
	filevault.Commands = []apple.Command{{ID: "e0000000-0000-4000-8000-000000000002", FileVault: true, Status: "failed", RequestType: "InstallProfile"}}
	filevaultFailure := filevault
	filevaultFailure.FileVault = &apple.FileVault{DeviceID: mac.ID, Desired: "enabled", Phase: "failed", Error: "escrow_profile_missing"}
	validationDetail := func(status string) Detail {
		d := filevault
		v := *filevault.FileVault
		v.Validation = &apple.FileVaultValidation{ID: "e0000000-0000-4000-8000-000000000003", Status: status, CreatedAt: now, CompletedAt: &now}
		if status != "queued" {
			v.VerifiedAt = &now
		}
		d.FileVault = &v
		return d
	}
	cases := []struct {
		name      string
		component templ.Component
		required  []string
	}{
		{"mac-filevault", DeviceDetails(c, info, filevault), []string{"FileVault disk encryption", "Profiles confirmed", "Not yet validated against the Mac volume", "Retrieve recovery key", "Disk encryption remains enabled", "Validate current recovery key"}},
		{"mac-filevault-validation-queued", DeviceDetails(c, info, validationDetail("queued")), []string{"Waiting for the Mac to validate the current key"}},
		{"mac-filevault-validation-valid", DeviceDetails(c, info, validationDetail("valid")), []string{"Validated on", "Validate current recovery key"}},
		{"mac-filevault-validation-invalid", DeviceDetails(c, info, validationDetail("invalid")), []string{"does not unlock its volume", "Validate current recovery key"}},
		{"mac-filevault-reader", DeviceDetails(c, &reader, filevault), []string{"FileVault disk encryption", "Profiles confirmed", "Not yet validated against the Mac volume"}},
		{"mac-filevault-failed", DeviceDetails(c, info, filevaultFailure), []string{"Encryption activation was not queued", "Enable FileVault with recovery escrow"}},
		{"devices", Devices(c, info, []DeviceRow{{ID: "windows-1", Name: "Finance Windows", Platform: "windows", OSVersion: "Windows 11", Status: "agent", LastSeen: &now, URL: "/tenant/1/computers/windows-1"}, {ID: d.ID, Name: d.Name, Platform: "iOS", OSVersion: d.OSVersion, Serial: d.SerialNumber, Status: d.Status, LastSeen: d.LastSeen, URL: "/tenant/1/ios/" + d.ID}}, "", "", ""), []string{"Finance Windows", "Sales iPhone", "Windows software deployment", "Apple profiles"}},
		{"device", DeviceDetails(c, info, detail), []string{"Installed apps", "Example app", "18.6.2", "22G100", "Enforce update policy", "test-csrf-token", `value="18.7.1/22H100"`, `value="18.7.1/22H6100"`, "Automatic renewal starts 30 days", "New push data received; awaiting command-channel confirmation", "New identity in use", strings.Repeat("2b", 32)}},
		{"mac-device", DeviceDetails(c, info, macDetail), []string{"Design Mac", "Mac management readiness", "Apple silicon", "Not escrowed", "J313AP", "Wait for this Mac to escrow", "Remove update policy", "Device channel"}},
		{"mac-linked", DeviceDetails(c, info, linked), []string{"Device identity", "Management channel history", "Open agent inventory and actions", linked.Mac.ID}},
		{"mac-linked-reader", DeviceDetails(c, &reader, linked), []string{"Device identity", "Management channel history", linked.Mac.ID}},
		{"mac-queued", DeviceDetails(c, info, queued), []string{"Cancel verification"}},
		{"mac-conflict", DeviceDetails(c, info, conflict), []string{"Conflicting evidence", "Retry profile cleanup"}},
		{"mac-cleanup", DeviceDetails(c, info, cleanup), []string{"Waiting for the Mac"}},
		{"mac-user", UserDetails(c, info, userDetail), []string{"Alice Example", "User profile assignments", "Refresh user profiles", "Apply to this user", "Pause this user", "Retry user command", "test-csrf-token"}},
		{"mac-user-reader", UserDetails(c, &reader, userDetail), []string{"Alice Example", "User profile assignments", "User command history"}},
		{"mac-user-paused", UserDetails(c, info, pausedDetail), []string{"Resume user management", "Installed profiles may remain"}},
		{"user-profiles", Profiles(c, info, []apple.Profile{userProfile}, []apple.Device{mac}), []string{"User scope", "Assign user profiles"}},
		{"profiles", Profiles(c, info, []apple.Profile{p}, []apple.Device{*d}), []string{"Create a Wi-Fi profile", "Save and deploy revision", "Company Wi-Fi", "test-csrf-token"}},
		{"setup", Setup(c, info, &apple.Settings{Organization: "Example organization", PublicURL: "https://mdm.example.test", Topic: "com.apple.mgmt.example", AppleAccount: "mdm-owner@example.test", PushCheckedAt: &now, PushFingerprint: strings.Repeat("b", 64), PushExpiresAt: now.AddDate(1, 0, 0)}, []apple.PushRequest{{ID: "30000000-0000-0000-0000-000000000001", Organization: "Example organization", PublicURL: "https://mdm.example.test", AppleAccount: "mdm-owner@example.test", ExpectedTopic: "com.apple.mgmt.example", BaseRevision: 1, Status: "pending", CreatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour), HasVendorRequest: true, VendorAvailable: true, VendorExpiresAt: &vendorExpires, VendorFingerprint: strings.Repeat("a", 64)}}, true, true, "", "", true), []string{"Create enrollment invitation", "push_certificate", "push_key", "test-csrf-token", "APNs connection checked (UTC)", strings.Repeat("b", 64), "Verify connection and import"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := tc.component.Render(ctx, &b); err != nil {
				t.Fatal(err)
			}
			html := b.String()
			if tc.name == "mac-filevault-reader" && (strings.Contains(html, "Retrieve recovery key") || strings.Contains(html, "Remove management profiles") || strings.Contains(html, "Validate current recovery key")) {
				t.Fatal("viewer has FileVault controls")
			}
			if tc.name == "mac-filevault-validation-queued" && strings.Contains(html, "Validate current recovery key") {
				t.Fatal("queued validation exposed duplicate form")
			}
			if tc.name == "mac-filevault" && strings.Contains(html, filevault.Commands[0].ID+"/retry") {
				t.Fatal("FileVault command exposes generic retry")
			}
			if tc.name == "mac-user-reader" && (strings.Contains(html, `action="/tenant/1`+userDetail.Path()+`/`) || strings.Contains(html, "Apply to this user")) {
				t.Fatal("viewer has user mutation controls")
			}
			if tc.name == "user-profiles" && strings.Contains(html, "Target devices") {
				t.Fatal("user profile exposes a device assignment")
			}

			if tc.name == "device" && (strings.Contains(html, detail.IdentityRenewals[0].CommandID+"/retry") || !strings.Contains(html, "60000000-0000-0000-0000-000000000001/retry")) {
				t.Fatal("renewal command retry was exposed or normal retry disappeared")
			}
			if tc.name == "mac-device" && !strings.Contains(html, `disabled>Enforce update policy`) {
				t.Fatal("unready Mac enforcement button is enabled")
			}
			if tc.name == "mac-linked-reader" && (strings.Contains(html, "Open agent inventory and actions") || strings.Contains(html, "Verify management channels")) {
				t.Fatal("canonical device granted a reader mutation controls")
			}
			if tc.name == "mac-cleanup" && (strings.Contains(html, "Retry profile cleanup") || strings.Contains(html, "90000000-0000-4000-8000-000000000001/retry") || strings.Contains(html, "Verify management channels")) {
				t.Fatal("pending cleanup exposed a replacement or generic retry")
			}
			for _, required := range tc.required {
				if !strings.Contains(html, required) {
					t.Errorf("missing %q", required)
				}
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, tc.name+".html"), b.Bytes(), 0644); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	malicious := *d
	malicious.Name = `<script>alert("xss")</script>`
	detail.Device = &malicious
	var b bytes.Buffer
	if err = DeviceDetails(c, info, detail).Render(ctx, &b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), malicious.Name) {
		t.Fatal("device-supplied name was emitted as executable HTML")
	}
	b.Reset()
	privateFingerprint := strings.Repeat("c", 64)
	if err = Setup(c, info, &apple.Settings{Organization: "Example organization", Topic: "com.apple.mgmt.example", PushCheckedAt: &now, PushFingerprint: privateFingerprint, PushReminders: reminders}, nil, false, true, "", "", true).Render(ctx, &b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), privateFingerprint) || strings.Contains(b.String(), "APNs connection checked (UTC)") || strings.Contains(b.String(), reminders[0].Fingerprint) {
		t.Fatal("connection metadata visible without certificate authority")
	}
	b.Reset()
	if err = Setup(c, info, &apple.Settings{Organization: "Example organization", PublicURL: "https://mdm.example.test", PushExpiresAt: now.Add(6 * 24 * time.Hour), PushReminders: reminders}, nil, true, false, "", "", true).Render(ctx, &b); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"Within 7 days", "Deliveries awaiting retry: 1", "Accepted by SMTP: 1", reminders[0].Fingerprint, "No eligible recipient"} {
		present := strings.Contains(b.String(), value)
		if (value == "No eligible recipient" && present) || (value != "No eligible recipient" && !present) {
			t.Errorf("incorrect reminder presentation for %q", value)
		}
	}
	if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
		if err = os.WriteFile(filepath.Join(dir, "reminders.html"), b.Bytes(), 0644); err != nil {
			t.Fatal(err)
		}
	}
}
