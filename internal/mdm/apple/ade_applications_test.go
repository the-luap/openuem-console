package apple

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/ade"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func adeAppFixture(t *testing.T) (*Store, *Device, *SoftwareVersion, ADEEnrollmentProfile) {
	t.Helper()
	s, server, f := adeEnrollmentStore(t)
	v, err := s.publishMacAppPackage(t.Context(), Scope{TenantID: 1}, testMacAppPackage(), "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	options := adeEnrollmentOptions()
	options.RequiredApplications = []string{v.ID}
	id, err := s.createADEProfile(t.Context(), 1, server, options, "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.publishADEProfile(t.Context(), 1, server, id); err != nil {
		t.Fatal(err)
	}
	p := adeProfileState(t, s, server, id)
	info := &ade.MachineInfo{Serial: "REQUIREDAPPMAC1", UDID: uuid.NewString(), Product: "Mac16,1", OSVersion: "15.0", Build: "24A335", SignerFingerprint: strings.Repeat("a", 64), SignedAt: time.Now()}
	adeAddSerial(t, s, f, server, info.Serial)
	if err = s.setADETargets(t.Context(), 1, server, p.ID, []string{info.Serial}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.reconcileADETargetBatch(t.Context(), 1, server); err != nil {
		t.Fatal(err)
	}
	definition := f.profiles[p.RemoteID]
	selector := definition.URL[strings.LastIndex(definition.URL, "/")+1:]
	profile, err := s.admitADE(t.Context(), selector, info)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := adeAuthenticate(t, s, info, profile, true)
	return s, d, v, p
}

func adeRequiredApp(t *testing.T, s *Store, d *Device) ADEApplication {
	t.Helper()
	items, err := s.ADEApplications(t.Context(), Scope{TenantID: d.TenantID, SiteID: d.SiteID}, d.ID)
	if err != nil || len(items) != 1 {
		t.Fatal("required application missing", err)
	}
	return items[0]
}

// Only synthetic device replies are emitted. No package is fetched or executed.
func adeAppReports(t *testing.T, s *Store, d *Device, wire map[string]any, version string) map[string]any {
	t.Helper()
	if wire == nil {
		wire = adeConnect(t, s, d, "Idle", "", nil)
	}
	for range 10 {
		if wire == nil {
			return nil
		}
		command := wire["Command"].(map[string]any)
		if command["RequestType"] == "DeviceConfigured" {
			return wire
		}
		fields := map[string]any{}
		switch command["RequestType"] {
		case "ManagedApplicationList":
			fields["ManagedApplicationList"] = map[string]any{"com.example.Editor": map[string]any{"Status": "Managed"}}
		case "InstalledApplicationList":
			fields["InstalledApplicationList"] = []any{map[string]any{"Identifier": "com.example.Editor", "Version": version}}
		case "DeviceInformation":
			fields["QueryResponses"] = map[string]any{"OSVersion": "15.0", "Model": "Mac16,1", "SerialNumber": "REQUIREDAPPMAC1", "AwaitingConfiguration": true}
		default:
			t.Fatal("unexpected command during app verification", command["RequestType"])
		}
		wire = adeConnect(t, s, d, "Acknowledged", wire["CommandUUID"].(string), fields)
	}
	t.Fatal("required application observations did not settle")
	return nil
}

func TestADERequiredApplicationWaitsForExactManagedVersion(t *testing.T) {
	s, d, v, p := adeAppFixture(t)
	r := adeRequiredApp(t, s, d)
	if len(p.RequiredApplications) != 1 || p.RequiredApplications[0] != v.ID || r.OriginalVersionID != v.ID || r.Version.ID != v.ID {
		t.Fatal("admission lost its immutable package revision")
	}
	adeSetupReady(t, s, d)
	if adeSetupCommand(t, s, d) != "" || adeSetupState(t, s, d).SetupError != "application_pending" {
		t.Fatal("setup released before required app installation")
	}
	wire := adeConnect(t, s, d, "Idle", "", nil)
	if wire == nil || wire["Command"].(map[string]any)["RequestType"] != "InstallEnterpriseApplication" {
		t.Fatal("required app was not queued")
	}
	install := wire["CommandUUID"].(string)
	wire = adeConnect(t, s, d, "Acknowledged", install, nil)
	if adeSetupCommand(t, s, d) != "" {
		t.Fatal("installer ACK released Setup Assistant")
	}
	if wire = adeAppReports(t, s, d, wire, "41.0"); wire != nil || adeSetupCommand(t, s, d) != "" {
		t.Fatal("wrong bundle version released setup")
	}
	r = adeRequiredApp(t, s, d)
	if err := s.changeMacApp(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, r.Assignment.ID, "refresh", "admin", nil); err != nil {
		t.Fatal(err)
	}
	wire = adeAppReports(t, s, d, nil, "42.0")
	if wire == nil || wire["Command"].(map[string]any)["RequestType"] != "DeviceConfigured" || adeRequiredApp(t, s, d).Error != "" {
		t.Fatal("verified required app did not permit setup release")
	}
	next := testMacAppPackage()
	next.Version = "43.0"
	v2, err := s.publishMacAppPackage(t.Context(), Scope{TenantID: 1}, next, "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.replaceADEApplication(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, r.ID, v2.ID, "Upgrade during setup", "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("a sent setup release permitted a new prerequisite", err)
	}
	adeConnect(t, s, d, "Error", wire["CommandUUID"].(string), map[string]any{"ErrorChain": []any{map[string]any{"LocalizedDescription": "Synthetic release failure"}}})
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.retryADESetupTx(t.Context(), tx, Scope{TenantID: 1, SiteID: 1}, d.ID, "admin"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if adeSetupState(t, s, d).CanChangeApplications {
		t.Fatal("retry forgot the previous release dispatch")
	}
	if err = s.replaceADEApplication(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, r.ID, v2.ID, "After release retry", "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("release retry reopened required application changes", err)
	}
	wire = adeAppReports(t, s, d, nil, "42.0")
	if wire == nil {
		t.Fatal("unchanged requirements could not retry setup release")
	}
	adeConnect(t, s, d, "Acknowledged", wire["CommandUUID"].(string), nil)
	if adeSetupState(t, s, d).SetupState == "complete" {
		t.Fatal("release ACK was confused with observed setup completion")
	}
	var installs int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_app_commands WHERE device_id=$1 AND kind='install'`, d.ID).Scan(&installs); err != nil || installs != 1 {
		t.Fatal("setup polling replayed the required installer", installs, err)
	}
}

func TestADERequiredAppWithdrawalReplacementAndHistory(t *testing.T) {
	s, d, v, p := adeAppFixture(t)
	adeExec(t, s, `UPDATE uem_software_versions SET withdrawn_at=clock_timestamp() WHERE id=$1`, v.ID)
	adeSetupReady(t, s, d)
	r := adeRequiredApp(t, s, d)
	if r.Error != "approval_withdrawn" || r.Assignment != nil || adeSetupCommand(t, s, d) != "" {
		t.Fatal("withdrawn prerequisite was executed or omitted")
	}
	next := testMacAppPackage()
	next.Version = "43.0"
	v2, err := s.publishMacAppPackage(t.Context(), Scope{TenantID: 1}, next, "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ReplaceADEApplication(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, r.ID, v2.ID, "Correct approved source", "admin", nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("replacement bypassed authority", err)
	}
	if err = s.replaceADEApplication(t.Context(), Scope{TenantID: 1, SiteID: 2}, d.ID, r.ID, v2.ID, "Correct approved source", "admin", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("replacement crossed site scope", err)
	}
	if err = s.replaceADEApplication(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, r.ID, v2.ID, "Correct approved source", "admin", nil); err != nil {
		t.Fatal(err)
	}
	r = adeRequiredApp(t, s, d)
	if r.OriginalVersionID != v.ID || r.Version.ID != v2.ID || r.Assignment == nil || r.Assignment.Version.ID != v2.ID {
		t.Fatal("replacement lost original intent or failed to queue the new revision")
	}
	stored, changes, cursor, err := s.ADEApplicationChanges(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, r.ID, "")
	if err != nil || stored.OriginalVersionID != v.ID || len(changes) != 1 || cursor != "" || changes[0].PreviousVersionID != v.ID || changes[0].VersionID != v2.ID || changes[0].Reason != "Correct approved source" {
		t.Fatal("scoped replacement history missing", err)
	}
	_, older, _, err := s.ADEApplicationChanges(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, r.ID, changes[0].ID)
	if err != nil || len(older) != 0 {
		t.Fatal("history cursor repeated its boundary", err)
	}
	for _, scope := range []Scope{{TenantID: 1, SiteID: 2}, {TenantID: 2}} {
		if _, _, _, err = s.ADEApplicationChanges(t.Context(), scope, d.ID, r.ID, changes[0].ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("history escaped device scope", err)
		}
	}
	if _, _, _, err = s.ADEApplicationChanges(t.Context(), Scope{TenantID: 1}, d.ID, r.ID, uuid.NewString()); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign history cursor accepted", err)
	}
	var previous, replacement, reason string
	var site int
	if err = s.db.QueryRow(`SELECT c.previous_version_id,c.version_id,c.reason,(a.details->>'site_id')::int FROM mdm_apple_ade_app_changes c JOIN mdm_apple_audit a ON a.resource_id=c.id::text AND a.action='apple.ade.application.replace' WHERE c.requirement_id=$1`, r.ID).Scan(&previous, &replacement, &reason, &site); err != nil || previous != v.ID || replacement != v2.ID || reason != "Correct approved source" || site != 1 {
		t.Fatal("replacement history or scoped audit missing", err)
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_ade_profile_apps SET version_id=$2 WHERE profile_id=$1`, p.ID, v2.ID); err == nil {
		t.Fatal("original profile requirement was mutable")
	}
	if _, err = s.db.Exec(`DELETE FROM mdm_apple_ade_profile_apps WHERE profile_id=$1`, p.ID); err == nil {
		t.Fatal("original profile requirement could be deleted")
	}

	if _, err = s.db.Exec(`DELETE FROM mdm_apple_ade_device_apps WHERE id=$1`, r.ID); err == nil {
		t.Fatal("device prerequisite could be silently removed")
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_ade_device_apps SET version_id=$2 WHERE id=$1`, r.ID, v.ID); err == nil {
		t.Fatal("revision changed without matching history")
	}
	wire := adeConnect(t, s, d, "Idle", "", nil)
	// Replacement also asks for a fresh hold report; its command can precede
	// the installer because ordinary query creation uses transaction time.
	if wire["Command"].(map[string]any)["RequestType"] == "DeviceInformation" {
		wire = adeConnect(t, s, d, "Acknowledged", wire["CommandUUID"].(string), map[string]any{"QueryResponses": map[string]any{"OSVersion": "15.0", "SerialNumber": "REQUIREDAPPMAC1", "AwaitingConfiguration": true}})
	}
	if wire == nil || wire["Command"].(map[string]any)["RequestType"] != "InstallEnterpriseApplication" {
		t.Fatal("replacement installer missing")
	}
	wire = adeConnect(t, s, d, "Acknowledged", wire["CommandUUID"].(string), nil)
	if wire = adeAppReports(t, s, d, wire, "43.0"); wire == nil || wire["Command"].(map[string]any)["RequestType"] != "DeviceConfigured" {
		t.Fatal("corrected prerequisite did not release setup")
	}
}

func TestADERequiredAppCancelledAndUnknownAttemptsAreNotReplayed(t *testing.T) {
	s, d, v, _ := adeAppFixture(t)
	adeSetupReady(t, s, d)
	r := adeRequiredApp(t, s, d)
	if err := s.changeMacApp(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, r.Assignment.ID, "cancel", "admin", nil); err != nil {
		t.Fatal(err)
	}
	adeExec(t, s, `UPDATE mdm_apple_ade_admissions SET next_setup_at=clock_timestamp() WHERE device_id=$1`, d.ID)
	if err := s.ReconcileADESetups(t.Context()); err != nil {
		t.Fatal(err)
	}
	if adeRequiredApp(t, s, d).Error != "operator_action_required" || adeSetupCommand(t, s, d) != "" {
		t.Fatal("cancelled app was silently skipped or retried")
	}
	if err := s.installMacApp(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, v.ID, "admin", MacAppInstallOptions{}, nil); err != nil {
		t.Fatal(err)
	}
	wire := adeConnect(t, s, d, "Idle", "", nil)
	id := wire["CommandUUID"].(string)
	adeExec(t, s, `UPDATE mdm_apple_commands SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id)
	adeConnect(t, s, d, "Idle", "", nil)
	next := testMacAppPackage()
	next.Version = "43.0"
	v2, err := s.publishMacAppPackage(t.Context(), Scope{TenantID: 1}, next, "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.replaceADEApplication(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, r.ID, v2.ID, "Replace uncertain install", "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("unknown installer permitted a different executable revision", err)
	}
	if adeRequiredApp(t, s, d).Version.ID != v.ID || adeSetupCommand(t, s, d) != "" {
		t.Fatal("blocked replacement mutated the requirement")
	}
}

func TestADERequiredAppPolicyRejectsInvalidOrAmbiguousVersions(t *testing.T) {
	s, server, _ := adeEnrollmentStore(t)
	v, err := s.publishMacAppPackage(t.Context(), Scope{TenantID: 1}, testMacAppPackage(), "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	input := testMacAppPackage()
	input.Version = "43.0"
	v2, err := s.publishMacAppPackage(t.Context(), Scope{TenantID: 1}, input, "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []func(*ADEProfileOptions){
		func(o *ADEProfileOptions) { o.RequiredApplications = []string{v.ID, v.ID} },
		func(o *ADEProfileOptions) { o.RequiredApplications = []string{v.ID, v2.ID} },
		func(o *ADEProfileOptions) { o.Platform = PlatformIOS; o.AllowDeviceLock = false },
		func(o *ADEProfileOptions) { o.AwaitConfiguration = false },
		func(o *ADEProfileOptions) { o.RequiredApplications = []string{uuid.Nil.String()} },
		func(o *ADEProfileOptions) { o.RequiredApplications = []string{uuid.NewString()} },
		func(o *ADEProfileOptions) {
			o.RequiredApplications = make([]string, 17)
			for i := range o.RequiredApplications {
				o.RequiredApplications[i] = uuid.NewString()
			}
		},
	}
	for i, change := range cases {
		o := adeEnrollmentOptions()
		o.RequiredApplications = []string{v.ID}
		change(&o)
		if _, err = s.createADEProfile(t.Context(), 1, server, o, "admin", nil); err == nil {
			t.Fatal("invalid required app policy accepted", i)
		}
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_ade_profiles WHERE server_id=$1`, server).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected policy left a publishable enrollment profile", count, err)
	}
	adeExec(t, s, `UPDATE uem_software_versions SET withdrawn_at=clock_timestamp() WHERE id=$1`, v.ID)
	o := adeEnrollmentOptions()
	o.RequiredApplications = []string{v.ID}
	if _, err = s.createADEProfile(t.Context(), 1, server, o, "admin", nil); err == nil {
		t.Fatal("withdrawn required revision accepted")
	}
}
