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
	operator := *info
	operator.Principal = access.Principal{UserID: "preview-operator", Grants: []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1}}}}
	lockMac := mac
	lockMac.DeviceLockAllowed = true
	lockDetail := macDetail
	lockDetail.Device = &lockMac
	queued := macDetail
	queued.MacBinding = &apple.MacBinding{Status: "queued", ExpiresAt: now.Add(time.Hour)}
	conflict := macDetail
	conflict.MacBinding = &apple.MacBinding{Status: "conflict", ExpiresAt: now.Add(time.Hour), InstalledAt: &now, CompletedAt: &now, CleanupAttempts: 1, CleanupStatus: "failed"}
	cleanup := linked
	cleanup.MacBinding = &apple.MacBinding{Status: "consumed", ExpiresAt: now.Add(time.Hour), InstalledAt: &now, CompletedAt: &now, CleanupAttempts: 1, CleanupStatus: "queued"}
	cleanup.Commands = []apple.Command{{ID: "90000000-0000-4000-8000-000000000001", RequestType: "RemoveProfile", Status: "failed", MacBinding: true}}

	user := &apple.UserChannel{ID: "a0000000-0000-4000-8000-000000000001", DeviceID: mac.ID, UserID: "b0000000-0000-4000-8000-000000000001", ShortName: "alice", LongName: "Alice Example", Status: "enrolled", PushStatus: "accepted", LastSeen: now, ProfilesAt: &now, InstalledProfiles: []apple.InstalledProfile{{Identifier: "com.example.user", UUID: "c0000000-0000-4000-8000-000000000001", Name: "User preferences"}}}
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
	rotationDetail := func(status string) Detail {
		d := validationDetail("valid")
		d.FileVault.Rotation = &apple.FileVaultRotation{ID: "e0000000-0000-4000-8000-000000000004", Status: status, CreatedAt: now, CompletedAt: &now}
		d.FileVault.RotationReady = status == "rotated" || status == "resolved"
		d.FileVault.ValidationReady = status != "queued" && status != "awaiting-stop"
		d.FileVault.Rotation.ExecutionStopped = status == "uncertain"
		if status == "awaiting-stop" {
			d.FileVault.Rotation.Status = "uncertain"
		}
		return d
	}
	recoveryDetail := func(status string) Detail {
		d := lockDetail
		r := &apple.RecoveryLock{Evidence: "unknown"}
		d.RecoveryLock = r
		if status != "new" {
			r.CurrentKeyID = "f0000000-0000-4000-8000-000000000001"
			r.Evidence = "verified"
			r.Attempt = &apple.RecoveryLockAttempt{ID: "f0000000-0000-4000-8000-000000000002", Operation: "rotate", Status: status, PreviousKeyID: r.CurrentKeyID, CandidateKeyID: "f0000000-0000-4000-8000-000000000003", CreatedAt: now}
			d.RecoveryLockKeys = []apple.RecoveryLockKey{{ID: r.CurrentKeyID, Source: "generated", Current: true, CreatedAt: now, VerifiedAt: &now}}
		}
		if status == "stopped" {
			r.Attempt.Status = "uncertain"
			r.Attempt.CanCheckPrevious = true
		}
		if status == "removal-uncertain" {
			r.Attempt.Status = "uncertain"
			r.Attempt.Operation = "remove"
			r.Attempt.CandidateKeyID = ""
			r.Attempt.Error = "awaiting_removal_result"
		}
		if status == "removed" {
			r.Evidence = "removal_acknowledged"
			r.CurrentKeyID = ""
			d.RecoveryLockKeys[0].Current = false
		}
		if status == "stale" {
			r.Attempt.Status = "verified"
			r.Reason = "Refresh device and security inventory before managing Recovery Lock."
		}
		d.Commands = []apple.Command{{ID: "f0000000-0000-4000-8000-000000000004", RecoveryLock: true, RequestType: "SetRecoveryLock", Status: "failed"}}
		return d
	}
	adeServer := apple.ADEServer{ID: "a0000000-0000-4000-8000-000000000001", Name: "Corporate Apple devices", Status: "connected", AppleServerID: "b0000000-0000-4000-8000-000000000001", AppleServerName: "Apple server", AppleOrganizationID: "100001", AppleOrganizationName: "Example organization", CertificateExpiresAt: now.AddDate(10, 0, 0), TokenExpiresAt: &vendorExpires, VerifiedAt: &now, SyncedAt: &now, NextSyncAt: &vendorExpires, SyncMode: "delta", Assigned: 1}
	adePending := adeServer
	adePending.Status = "pending"
	adePending.TokenExpiresAt = nil
	adeDisabled := adeServer
	adeDisabled.Status = "disabled"
	adeThrottled := adeServer
	adeThrottled.SyncError = "throttled"
	adeThrottled.RetryAfter = &vendorExpires
	adeDevices := []apple.ADEDevice{{Serial: "SYNTHETIC1", Model: "MacBook Pro", Family: "Mac", OS: "OSX", ProfileStatus: "empty", Assigned: true, ObservedAt: now}, {Serial: "SYNTHETIC2", Model: "iPhone", Family: "iPhone", OS: "iOS", ProfileStatus: "removed", ObservedAt: now}}
	adeProfile := apple.ADEEnrollmentProfile{ID: "c0000000-0000-4000-8000-000000000001", ServerID: adeServer.ID, Name: "Corporate Mac <profile>", SiteID: 1, Platform: apple.PlatformMacOS, Status: "published", RemoteID: "SYNTHETICREMOTE1", AwaitConfiguration: true, DeviceLockAllowed: true}
	adeUnknown := adeProfile
	adeUnknown.ID = "c0000000-0000-4000-8000-000000000002"
	adeUnknown.Status = "unknown"
	adeUnknown.RemoteID = ""
	adeUnknown.Error = "publication_uncertain"
	adeEnrollment := ADEEnrollment{Profiles: []apple.ADEEnrollmentProfile{adeProfile, adeUnknown}, Targets: []apple.ADETarget{{Serial: "SYNTHETIC1", ProfileID: adeProfile.ID, Status: "accepted"}, {Serial: "SYNTHETIC2", ProfileID: adeProfile.ID, Status: "observed", DeviceID: mac.ID, DeviceStatus: "revoked", SetupState: "cancelled", ObservedAt: &now}}, Next: "SYNTHETIC2"}
	adeMac := mac
	adeMac.EnrollmentMethod = "automated_device"
	adeDetail := macDetail
	adeDetail.Device = &adeMac
	adeDetail.ADE = &apple.ADEDeviceEnrollment{ServerID: adeServer.ID, ProfileID: adeProfile.ID, ProfileName: adeProfile.Name, SetupState: "failed", SetupError: "command_failed", SetupUpdatedAt: &now}
	adeDetail.Commands = []apple.Command{{ID: "c0000000-0000-4000-8000-000000000003", RequestType: "DeviceConfigured", Status: "failed", ADESetup: true}}

	adminDevice := mac
	adminDevice.EnrollmentMethod = "automated_device"
	adminAccount := &apple.MacAdminAccount{Options: apple.MacAdminOptions{ShortName: "localadmin", FullName: "Managed <Admin>", PrimaryAccount: "standard", RotationDays: 30}, CreationState: "accepted", GUID: "f0000000-0000-4000-8000-000000000010", InventoryState: "present", ObservedAt: &now, AcceptedAt: &now, LatestStatus: "acknowledged", LatestOperation: "create", CurrentKeyID: "f0000000-0000-4000-8000-000000000011"}
	adminDetail := Detail{Device: &adminDevice, MacAdmin: adminAccount, ADE: &apple.ADEDeviceEnrollment{SetupState: "complete"}, MacAdminKeys: []apple.MacAdminKey{{ID: adminAccount.CurrentKeyID, Current: true, Operation: "create", Status: "acknowledged", CreatedAt: now}}, Commands: []apple.Command{{ID: "f0000000-0000-4000-8000-000000000012", MacAdmin: true, RequestType: "SetAutoAdminPassword", Status: "failed"}}}
	pausedAdmin := *adminAccount
	pausedAdmin.RotationPaused = true
	pausedAdminDetail := adminDetail
	pausedAdminDetail.MacAdmin = &pausedAdmin
	uncertainAdmin := *adminAccount
	uncertainAdmin.LatestStatus = "uncertain"
	uncertainDetail := adminDetail
	uncertainDetail.MacAdmin = &uncertainAdmin
	failedAdmin := *adminAccount
	failedAdmin.CreationState = "failed"
	failedAdmin.LatestStatus = "failed"
	failedDetail := adminDetail
	failedDetail.MacAdmin = &failedAdmin
	adminAwaiting := true
	failedDetail.ADE = &apple.ADEDeviceEnrollment{SetupState: "awaiting", AwaitingConfiguration: &adminAwaiting}

	appDevice := adminDevice
	appVersion := apple.SoftwareVersion{ID: "90000000-0000-4000-8000-000000000020", PackageID: "90000000-0000-4000-8000-000000000021", Platform: "macos", Name: "Editor <Suite>", Identifier: "com.example.Editor", Version: "42.0", Architecture: "universal", MinimumOS: "14.0", SHA256: strings.Repeat("a", 64), ApprovedAt: now, ApprovedBy: "Package administrator"}
	withdrawnVersion := appVersion
	withdrawnVersion.WithdrawnAt = &now
	appState := func(status string) []apple.MacAppAssignment {
		a := apple.MacAppAssignment{ID: "90000000-0000-4000-8000-000000000022", AttemptID: "90000000-0000-4000-8000-000000000023", DeviceID: appDevice.ID, Version: appVersion, Operation: "install", Status: status, CreatedAt: now, RequestedBy: "Site operator", ManagedState: "managed", ManagedAt: &now, InstalledState: "installed", InstalledVersion: "41.0", InstalledAt: &now, DispatchedAt: &now, AcceptedAt: &now}
		if status == "verified" {
			a.InstalledVersion = "42.0"
		}
		if status == "queued" {
			a.DispatchedAt = nil
			a.AcceptedAt = nil
			a.ManagedAt = nil
			a.InstalledAt = nil
			a.InstalledVersion = ""
			a.ManagedState = "unknown"
			a.InstalledState = "unknown"
		}
		return []apple.MacAppAssignment{a}
	}
	appHistory := append(appState("verified"), appState("cancelled")...)
	appHistory[1].Version.Version = "41.0"
	appHistory[1].AttemptID = "90000000-0000-4000-8000-000000000024"
	priorApp := apple.MacAppPriorAttempt{ID: "90000000-0000-4000-8000-000000000030", PreviousDeviceID: "90000000-0000-4000-8000-000000000031", PreviousName: "Earlier <Site>", PreviousStatus: "unenrolled", Operation: "install", Status: "uncertain", Version: appVersion, CreatedAt: now, DispatchedAt: &now}
	resolvedApp := priorApp
	resolvedApp.Recovery = &apple.MacAppRecovery{ID: "90000000-0000-4000-8000-000000000032", DeviceID: appDevice.ID, Evidence: "device_erased", Reason: "Synthetic erase <evidence>", Actor: "Operator <A>", CreatedAt: now}
	adeProfile.RequiredApplications = []string{appVersion.ID}
	adeProfile.PlatformSSO = &apple.ADEPlatformSSOOptions{ProfileRevisionID: "a0000000-0000-4000-8000-000000000030", ApplicationVersionID: appVersion.ID, ProviderConfirmed: true, ApprovalReason: "Reviewed <provider> extension"}
	adeEnrollment.Profiles[0] = adeProfile
	adeAppState := func(status string, changeable bool) Detail {
		d := Detail{Device: &appDevice, ADE: &apple.ADEDeviceEnrollment{SetupState: "awaiting", SetupError: "application_pending", CanChangeApplications: changeable}}
		a := appState(status)[0]
		d.ADEApplications = []apple.ADEApplication{{ID: "90000000-0000-4000-8000-000000000025", OriginalVersionID: appVersion.ID, Version: appVersion, Assignment: &a, Error: "application_pending"}}
		return d
	}
	adeAppChanges := []apple.ADEApplicationChange{{ID: "90000000-0000-4000-8000-000000000026", PreviousVersionID: appHistory[1].Version.ID, PreviousVersion: "41.0", VersionID: appVersion.ID, Version: appVersion.Version, Actor: "Operator <A>", Reason: "Correct <version> for setup", CreatedAt: now}}
	profileRevision := apple.ProfileRevision{ID: "a0000000-0000-4000-8000-000000000030", ProfileID: p.ID, Name: "Identity <configuration>", Identifier: p.Identifier, UUID: p.UUID, Scope: "System", Revision: 1, CurrentRevision: 2, PayloadTypes: []string{"com.apple.extensiblesso"}, Origin: "save", Actor: "Operator <A>", CreatedAt: now}
	profileRestored := profileRevision
	profileRestored.ID = "a0000000-0000-4000-8000-000000000031"
	profileRestored.Revision, profileRestored.CurrentRevision = 3, 3
	profileRestored.Origin, profileRestored.RestoredFrom, profileRestored.Reason = "restore", profileRevision.ID, "Restore <approved> identity settings"
	profileDeleted := profileRevision
	profileDeleted.CurrentRevision = 0
	profileMigrated := profileRevision
	profileMigrated.Origin, profileMigrated.Actor = "migration", ""
	ssoRequirement := apple.ADEPlatformSSOStatus{BindingRevisionID: "a0000000-0000-4000-8000-000000000032", PackageID: appVersion.PackageID, ID: "a0000000-0000-4000-8000-000000000032", ProfileID: p.ID, ProfileRevisionID: profileRevision.ID, ProfileName: profileRevision.Name, ProfileIdentifier: p.Identifier, ProfileRevision: 1, ApplicationVersionID: appVersion.ID, ApplicationName: appVersion.Name, ApplicationVersion: appVersion.Version, ApprovedBy: "Operator <A>", ApprovalReason: "Reviewed <provider> extension", Error: "profile_attention_required", CanRepair: true}
	ssoState := func(state string) Detail {
		r := ssoRequirement
		d := Detail{Device: &appDevice, ADE: &apple.ADEDeviceEnrollment{SetupState: "awaiting"}, ADEPlatformSSO: &r}
		if state == "verified" {
			r.ProfileVerified = true
			r.Error = ""
			r.ProfileObservedAt = &now
		}
		if state == "released" {
			r.CanRepair = false
			r.ProfileVerified = true
			d.ADE.SetupState = "releasing"
		}
		if state == "complete" {
			r.CanRepair = false
			d.ADE.SetupState = "complete"
		}
		return d
	}
	ssoRepairs := []apple.ADEPlatformSSORepair{{ID: "a0000000-0000-4000-8000-000000000033", ProfileRevisionID: profileRevision.ID, Actor: "Operator <A>", Reason: "Repair <profile> delivery", CreatedAt: now}}
	ssoRevisions := []apple.ADEPlatformSSORevision{{ID: ssoRequirement.BindingRevisionID, PreviousID: "a0000000-0000-4000-8000-000000000034", ProfileRevisionID: profileRevision.ID, ProfileName: profileRevision.Name, ProfileRevision: 2, ApplicationVersionID: appVersion.ID, ApplicationName: appVersion.Name, ApplicationVersion: "43.0", Actor: "Operator <A>", Reason: "Reviewed <correction>", CreatedAt: now}, {ID: "a0000000-0000-4000-8000-000000000034", ProfileRevisionID: profileRevision.ID, ProfileName: profileRevision.Name, ProfileRevision: 1, ApplicationVersionID: appVersion.ID, ApplicationName: appVersion.Name, ApplicationVersion: "42.0", Actor: "Original reviewer", Reason: "Original provider review", CreatedAt: now}}
	cases := []struct {
		name      string
		component templ.Component
		required  []string
	}{
		{"ade-sso-revisions", ADEPlatformSSORevisions(c, info, &appDevice, &ssoRequirement, ssoRevisions, ssoRevisions[1].ID), []string{"Original enrollment requirement", "Current required pair", "Reviewed &lt;correction&gt;", "Older provider revisions"}},
		{"ade-sso-attention", DeviceDetails(c, info, ssoState("attention")), []string{"Platform SSO setup requirement", "installation needs attention", "Send retained profile revision", "Reviewed &lt;provider&gt; extension", "Profile repair history"}},
		{"ade-sso-verified", DeviceDetails(c, info, ssoState("verified")), []string{"retained profile revision is verified by current inventory", "Send retained profile revision"}},
		{"ade-sso-released", DeviceDetails(c, info, ssoState("released")), []string{"Platform SSO setup requirement", "registration starts after release"}},
		{"ade-sso-complete", DeviceDetails(c, info, ssoState("complete")), []string{"The Mac reported that the MDM setup hold ended", "reviewed enrollment requirement"}},
		{"ade-sso-reader", DeviceDetails(c, &reader, ssoState("attention")), []string{"Platform SSO setup requirement", "Profile repair history"}},
		{"ade-sso-history", ADEPlatformSSORepairs(c, &reader, &appDevice, &ssoRequirement, ssoRepairs, ssoRepairs[0].ID), []string{"Platform SSO profile repairs", "Repair &lt;profile&gt; delivery", "Operator &lt;A&gt;", "Older profile repairs"}},
		{"ade-sso-history-empty", ADEPlatformSSORepairs(c, &reader, &appDevice, &ssoRequirement, nil, ""), []string{"No recorded profile repairs on this page"}},
		{"profile-history-restore", ProfileRevisionHistory(c, info, p.ID, []apple.ProfileRevision{profileRevision}, profileRevision.ID, true), []string{"Identity &lt;configuration&gt;", "Restore and deploy revision", "Download stored revision", "Older revisions"}},
		{"profile-history-current", ProfileRevisionHistory(c, info, p.ID, []apple.ProfileRevision{profileRestored}, "", true), []string{"Restored as a new revision", "Restore &lt;approved&gt; identity settings", "Current catalog revision"}},
		{"profile-history-deleted", ProfileRevisionHistory(c, info, "", []apple.ProfileRevision{profileDeleted}, "", true), []string{"catalog entry was deleted", "Download stored revision", "View this profile's history"}},
		{"profile-history-migrated", ProfileRevisionHistory(c, info, p.ID, []apple.ProfileRevision{profileMigrated}, "", true), []string{"Existing revision captured during migration", "Earlier versions and their authors were not retained"}},
		{"profile-history-reader", ProfileRevisionHistory(c, &reader, p.ID, []apple.ProfileRevision{profileRevision}, "", false), []string{"Profile revision history", "Identity &lt;configuration&gt;"}},
		{"profile-history-empty", ProfileRevisionHistory(c, info, "", nil, "", true), []string{"No stored profile revisions"}},
		{"software-prior-unresolved", MacAppPreviousEnrollments(c, info, &appDevice, apple.MacAppEnrollmentRisk{Unresolved: true}, []apple.MacAppPriorAttempt{priorApp}, priorApp.ID), []string{"Earlier &lt;Site&gt;", "Record stopping evidence", `name="confirmed"`, "Older operations"}},
		{"software-prior-resolved", MacAppPreviousEnrollments(c, info, &appDevice, apple.MacAppEnrollmentRisk{}, []apple.MacAppPriorAttempt{resolvedApp}, ""), []string{"Stopping evidence recorded", "Synthetic erase &lt;evidence&gt;", "Operator &lt;A&gt;", "Old outcome unknown"}},
		{"software-prior-duplicate", MacAppPreviousEnrollments(c, info, &appDevice, apple.MacAppEnrollmentRisk{ActiveIdentity: true, Unresolved: true}, []apple.MacAppPriorAttempt{priorApp}, ""), []string{"Another enrollment with this Mac identity is still active"}},
		{"software-prior-risk-reader", MacApplications(c, &reader, &appDevice, nil, "", apple.MacAppEnrollmentRisk{Unresolved: true}), []string{"An earlier enrollment"}},
		{"ade-app-queued", DeviceDetails(c, info, adeAppState("queued", true)), []string{"Required setup applications", "Replace required revision", "Select approved application revisions", "Editor &lt;Suite&gt;"}},
		{"ade-app-uncertain", DeviceDetails(c, info, adeAppState("uncertain", true)), []string{"Required setup applications", "Outcome unknown"}},
		{"ade-app-release-sent", DeviceDetails(c, info, adeAppState("verified", false)), []string{"Required setup applications", "Expected managed app version reported"}},
		{"ade-app-reader", DeviceDetails(c, &reader, adeAppState("queued", true)), []string{"Required setup applications", "Required revision history"}},
		{"ade-app-history", ADEApplicationHistory(c, &reader, &appDevice, adeAppState("queued", true).ADEApplications[0], adeAppChanges, adeAppChanges[0].ID), []string{"Required application history", "Original enrollment requirement", "Operator &lt;A&gt;", "Correct &lt;version&gt; for setup", "Older revision changes"}},

		{"software-catalog", SoftwareCatalog(c, info, []apple.SoftwareVersion{appVersion, withdrawnVersion}, appVersion.ID, true), []string{"Approve a Mac application package", "Editor &lt;Suite&gt;", "Older revisions", "Withdrawn", `name="sha256"`, `name="source_url"`}},
		{"software-catalog-reader", SoftwareCatalog(c, &reader, []apple.SoftwareVersion{appVersion}, "", false), []string{"Published revisions", "Editor &lt;Suite&gt;"}},
		{"software-version", SoftwareVersion(c, info, appVersion, []apple.Device{appDevice}, true, SoftwareDeviceSearch{Next: appDevice.ID}), []string{"Request installation", "Withdraw approval", "Exact bundle version", "Search Macs", "More matching Macs", strings.Repeat("a", 64)}},
		{"software-version-reader", SoftwareVersion(c, &reader, appVersion, nil, false, SoftwareDeviceSearch{}), []string{"Approved artifact", strings.Repeat("a", 64)}},
		{"software-version-withdrawn", SoftwareVersion(c, info, withdrawnVersion, nil, true, SoftwareDeviceSearch{}), []string{"Withdrawn at", "cannot be sent for another installation"}},
		{"software-app-queued", MacApplications(c, info, &appDevice, appState("queued"), ""), []string{"Cancel queued operation", "Queued for delivery", "View operation history"}},
		{"software-app-verifying", MacApplications(c, info, &appDevice, appState("verifying"), ""), []string{"Waiting for application observations", "41.0", "Request current app status"}},
		{"software-app-verified", MacApplications(c, info, &appDevice, appState("verified"), ""), []string{"Expected managed app version reported", "Request app removal", "42.0"}},
		{"software-app-uncertain", MacApplications(c, info, &appDevice, appState("uncertain"), ""), []string{"Outcome unknown", "Another mutation remains blocked", "Request current app status"}},
		{"software-app-reader", MacApplications(c, &reader, &appDevice, appState("verified"), ""), []string{"Expected managed app version reported", "View operation history"}},
		{"software-app-history", MacApplicationHistory(c, &reader, &appDevice, appHistory[0].ID, appHistory, appHistory[1].AttemptID), []string{"Application operation history", "does not establish the current installed state", "Cancelled before confirmed execution", "Older operations", "Site operator"}},
		{"mac-admin-paused", DeviceDetails(c, info, pausedAdminDetail), []string{"Automatic rotation is paused", "Resume automatic rotation", "Not scheduled"}},
		{"mac-admin-ready", DeviceDetails(c, info, adminDetail), []string{"Rotate administrator password", "Reveal password", "Managed &lt;Admin&gt;", "Last acknowledged password"}},
		{"mac-admin-uncertain", DeviceDetails(c, info, uncertainDetail), []string{"outcome is unknown", "Reveal password"}},
		{"mac-admin-failed", DeviceDetails(c, info, failedDetail), []string{"Retry account configuration"}},
		{"mac-admin-reader", DeviceDetails(c, &reader, adminDetail), []string{"Managed Mac administrator", "Account reported"}},
		{"ade-enrollment", ADE(c, info, []apple.ADEServer{adeServer}, adeServer.ID, adeDevices, "", adeEnrollment), []string{"Queue profile publication", "Publication outcome unknown", "Assignment accepted; verification pending", "Allow next activation", "Corporate Mac &lt;profile&gt;", "Next enrollments", "Select the Platform SSO profile revision", "Provider registration starts after release", "Reviewed &lt;provider&gt; extension", `name="enable_platform_sso"`, "data-sso-fields hidden disabled"}},
		{"ade-enrollment-disabled", ADE(c, info, []apple.ADEServer{adeDisabled}, adeServer.ID, adeDevices, "", adeEnrollment), []string{"Apple assignment verified", "Corporate Mac &lt;profile&gt;"}},
		{"ade-setup-failed", DeviceDetails(c, info, adeDetail), []string{"Automated Device Enrollment", "Retry setup release", "Removal disallowed"}},
		{"ade-setup-reader", DeviceDetails(c, &reader, adeDetail), []string{"Automated Device Enrollment", "Removal disallowed"}},
		{"mac-recovery-new", DeviceDetails(c, info, recoveryDetail("new")), []string{"Set a Recovery Lock password", "Import an existing Recovery Lock password", "confirm_recovery_lock"}},
		{"mac-recovery-verified", DeviceDetails(c, info, recoveryDetail("verified")), []string{"Rotate the Recovery Lock password", "Remove the Recovery Lock password", "Retrieve Recovery Lock password"}},
		{"mac-recovery-checking", DeviceDetails(c, info, recoveryDetail("checking")), []string{"verify the current password before changing it"}},
		{"ade-empty", ADE(c, info, nil, "", nil, ""), []string{"Create a connection", "An Apple server assignment does not confirm MDM enrollment"}},
		{"ade-pending", ADE(c, info, []apple.ADEServer{adePending}, adeServer.ID, nil, ""), []string{"Download public certificate", "Verify and import token", "Waiting for a verified Apple server token"}},
		{"ade-connected", ADE(c, info, []apple.ADEServer{adeServer}, adeServer.ID, adeDevices, "SYNTHETIC2"), []string{"Schedule synchronization", "SYNTHETIC1", "Removed", "Next page"}},
		{"ade-disabled", ADE(c, info, []apple.ADEServer{adeDisabled}, adeServer.ID, adeDevices, ""), []string{"Synchronization is disabled", "SYNTHETIC2"}},
		{"ade-throttled", ADE(c, info, []apple.ADEServer{adeThrottled}, adeServer.ID, adeDevices, ""), []string{"Apple requested a later retry", "Apple retry deadline"}},
		{"mac-recovery-uncertain", DeviceDetails(c, info, recoveryDetail("uncertain")), []string{"Another password change remains blocked", "Check proposed password"}},
		{"mac-recovery-stopped", DeviceDetails(c, info, recoveryDetail("stopped")), []string{"Check retained previous password"}},
		{"mac-recovery-removal-uncertain", DeviceDetails(c, info, recoveryDetail("removal-uncertain")), []string{"has not confirmed whether the password was removed"}},
		{"mac-recovery-removed", DeviceDetails(c, info, recoveryDetail("removed")), []string{"Absence of a password has not been independently verified", "Set a Recovery Lock password"}},
		{"mac-recovery-stale", DeviceDetails(c, info, recoveryDetail("stale")), []string{"Refresh device and security inventory"}},
		{"mac-recovery-reader", DeviceDetails(c, &reader, recoveryDetail("verified")), []string{"Stored password verified by the Mac"}},
		{"mac-recovery-operator", DeviceDetails(c, &operator, recoveryDetail("verified")), []string{"Stored password verified by the Mac"}},
		{"setup-device-lock-admin", Setup(c, info, &apple.Settings{Organization: "Example organization", PublicURL: "https://mdm.example.test", PushExpiresAt: now.AddDate(1, 0, 0)}, nil, true, true, "", "", true), []string{"Allow Recovery Lock and device lock management", `name="allow_mac_device_lock"`, "Existing enrollments cannot gain these rights through renewal"}},
		{"setup-device-lock-operator", Setup(c, &operator, &apple.Settings{Organization: "Example organization", PublicURL: "https://mdm.example.test", PushExpiresAt: now.AddDate(1, 0, 0)}, nil, true, true, "", "", true), []string{"Create enrollment invitation"}},
		{"setup-device-lock-reader", Setup(c, &reader, &apple.Settings{Organization: "Example organization", PublicURL: "https://mdm.example.test", PushExpiresAt: now.AddDate(1, 0, 0)}, nil, true, true, "", "", true), []string{"Apple setup"}},
		{"mac-device-lock-allowed", DeviceDetails(c, info, lockDetail), []string{"Included in this enrollment", "does not indicate whether a Recovery Lock password is set"}},
		{"mac-filevault-rotation-ready", DeviceDetails(c, info, rotationDetail("rotated")), []string{"New recovery key stored and validated", "Rotate current recovery key", "/rotate"}},
		{"mac-filevault-rotation-queued", DeviceDetails(c, info, rotationDetail("queued")), []string{"Waiting for the Mac to replace its recovery key"}},
		{"mac-filevault-rotation-awaiting-stop", DeviceDetails(c, info, rotationDetail("awaiting-stop")), []string{"has not confirmed that the command stopped", "Key validation and another rotation remain blocked"}},
		{"mac-filevault-rotation-uncertain", DeviceDetails(c, info, rotationDetail("uncertain")), []string{"Another rotation remains blocked", "Validate current recovery key"}},
		{"mac-filevault-rotation-unverified", DeviceDetails(c, info, rotationDetail("unverified")), []string{"New recovery key stored; validate it"}},
		{"mac-filevault-rotation-resolved", DeviceDetails(c, info, rotationDetail("resolved")), []string{"uncertain attempt is resolved", "Rotate current recovery key"}},
		{"mac-filevault-rotation-reader", DeviceDetails(c, &reader, rotationDetail("rotated")), []string{"New recovery key stored and validated"}},
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
		{"profiles", Profiles(c, info, []apple.Profile{p}, []apple.Device{*d}), []string{"Create a Wi-Fi profile", "Create a Mac firewall profile", "Create a Mac Platform SSO profile", "Create a Mac Gatekeeper profile", "Create a Mac System Extensions profile", "Create a Mac privacy profile (PPPC/TCC)", "Receiver code requirement", "Create a public certificate profile", "Public certificates (PEM or DER, up to 256 KiB)", "Prevent removal from System Settings and Finder", "Blocked malware submission prompt", "Deleting this catalog entry retains its encrypted revision history.", "Provider registration token", "Allowed applications", "Save and deploy revision", "Company Wi-Fi", "test-csrf-token"}},
		{"setup", Setup(c, info, &apple.Settings{Organization: "Example organization", PublicURL: "https://mdm.example.test", Topic: "com.apple.mgmt.example", AppleAccount: "mdm-owner@example.test", PushCheckedAt: &now, PushFingerprint: strings.Repeat("b", 64), PushExpiresAt: now.AddDate(1, 0, 0)}, []apple.PushRequest{{ID: "30000000-0000-0000-0000-000000000001", Organization: "Example organization", PublicURL: "https://mdm.example.test", AppleAccount: "mdm-owner@example.test", ExpectedTopic: "com.apple.mgmt.example", BaseRevision: 1, Status: "pending", CreatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour), HasVendorRequest: true, VendorAvailable: true, VendorExpiresAt: &vendorExpires, VendorFingerprint: strings.Repeat("a", 64)}}, true, true, "", "", true), []string{"Create enrollment invitation", "push_certificate", "push_key", "test-csrf-token", "APNs connection checked (UTC)", strings.Repeat("b", 64), "Verify connection and import"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := tc.component.Render(ctx, &b); err != nil {
				t.Fatal(err)
			}
			html := b.String()
			if tc.name == "ade-sso-released" || tc.name == "ade-sso-complete" || tc.name == "ade-sso-reader" {
				if strings.Contains(html, "Send retained profile revision") || strings.Contains(html, "Apply reviewed provider revisions") {
					t.Fatal("repair exposed after release or without permission")
				}
			}
			if tc.name == "profile-history-current" || tc.name == "profile-history-deleted" || tc.name == "profile-history-reader" || tc.name == "profile-history-empty" {
				if strings.Contains(html, "Restore and deploy revision") {
					t.Fatal("unavailable historical restoration is exposed")
				}
			}
			if tc.name == "profile-history-reader" && strings.Contains(html, "Download stored revision") {
				t.Fatal("reader sees protected revision download")
			}
			if tc.name == "software-prior-resolved" || tc.name == "software-prior-duplicate" || tc.name == "software-prior-risk-reader" {
				if strings.Contains(html, `name="evidence"`) {
					t.Fatal("blocked or resolved operation exposes evidence mutation")
				}
			}
			if tc.name == "software-prior-risk-reader" && (strings.Contains(html, "Review previous enrollments") || strings.Contains(html, priorApp.ID)) {
				t.Fatal("reader sees cross-site history")
			}
			if tc.name == "ade-app-uncertain" || tc.name == "ade-app-release-sent" || tc.name == "ade-app-reader" {
				if strings.Contains(html, "Replace required revision") || strings.Contains(html, "data-app-search") {
					t.Fatal("blocked required revision exposes correction form")
				}
			}
			if strings.HasSuffix(tc.name, "reader") && strings.HasPrefix(tc.name, "software-") {
				for _, forbidden := range []string{"Request installation", "Request app removal", "Cancel queued operation", "Request current app status", "Approve package revision", "Withdraw approval"} {
					if strings.Contains(html, forbidden) {
						t.Fatalf("reader sees software mutation: %s", forbidden)
					}
				}
			}
			if tc.name == "software-version-withdrawn" && (strings.Contains(html, "Request installation") || strings.Contains(html, "Withdraw approval")) {
				t.Fatal("withdrawn revision offers mutation")
			}
			if tc.name == "software-app-uncertain" || tc.name == "software-app-verifying" {
				if strings.Contains(html, "Request app removal") || strings.Contains(html, "Cancel queued operation") {
					t.Fatal("unresolved mutation offers unsafe action")
				}
			}

			if strings.HasPrefix(tc.name, "mac-admin-") && strings.Contains(html, "f0000000-0000-4000-8000-000000000012/retry") {
				t.Fatal("administrator mutation has generic retry")
			}
			if tc.name == "mac-admin-uncertain" && strings.Contains(html, "Rotate administrator password") {
				t.Fatal("uncertain operation exposes rotation")
			}
			if tc.name == "mac-admin-reader" && (strings.Contains(html, "Reveal password") || strings.Contains(html, "Rotate administrator password") || strings.Contains(html, "Retry account configuration")) {
				t.Fatal("reader sees password actions")
			}

			if strings.HasPrefix(tc.name, "ade-setup-") && strings.Contains(html, "commands/c0000000-0000-4000-8000-000000000003/retry") {
				t.Fatal("setup command exposes generic retry")
			}
			if tc.name == "ade-setup-reader" && strings.Contains(html, "setup/retry") {
				t.Fatal("viewer has setup retry controls")
			}
			if tc.name == "ade-enrollment-disabled" && (strings.Contains(html, "Queue profile publication") || strings.Contains(html, "Save desired assignments") || strings.Contains(html, "Allow next activation")) {
				t.Fatal("disabled connection permits enrollment mutation")
			}
			if tc.name == "mac-filevault-rotation-awaiting-stop" && (strings.Contains(html, "Validate current recovery key") || strings.Contains(html, "Rotate current recovery key")) {
				t.Fatal("FileVault recovery actions offered without stopping evidence")
			}
			if strings.HasPrefix(tc.name, "mac-recovery-") {
				if strings.Contains(html, "f0000000-0000-4000-8000-000000000004/retry") {
					t.Fatal("password command exposes generic retry")
				}
				if tc.name == "mac-recovery-reader" || tc.name == "mac-recovery-operator" {
					if strings.Contains(html, "/recovery-lock") {
						t.Fatal("unprivileged Recovery Lock form")
					}
				}
				if tc.name == "mac-recovery-checking" || tc.name == "mac-recovery-uncertain" || tc.name == "mac-recovery-removal-uncertain" || tc.name == "mac-recovery-stale" {
					if strings.Contains(html, `name="operation" value="rotate"`) || strings.Contains(html, `name="operation" value="remove"`) || strings.Contains(html, `name="operation" value="import"`) {
						t.Fatal("blocked password change offered")
					}
				}
				if tc.name == "mac-recovery-uncertain" && strings.Contains(html, "Check retained previous password") {
					t.Fatal("old password check lacks stopping proof")
				}
			}

			if (tc.name == "setup-device-lock-operator" || tc.name == "setup-device-lock-reader") && strings.Contains(html, `name="allow_mac_device_lock"`) {
				t.Fatal("lock rights offered without device security permission")
			}
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
			if strings.HasPrefix(tc.name, "mac-user") && (strings.Contains(html, "Not reported as managed") || !strings.Contains(html, "a new inventory report must contain the assigned profile UUID")) {
				t.Fatal("Mac user inventory misrepresents the absent IsManaged field")
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
