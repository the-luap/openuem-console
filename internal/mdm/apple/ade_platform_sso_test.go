package apple

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/ade"
	"github.com/open-uem/openuem-console/internal/security/access"
	"howett.net/plist"
)

func adeSSOPayload(t *testing.T, registration, firstUser any) []byte {
	t.Helper()
	settings := platformSSOSettings()
	settings["AuthenticationMethod"] = "Password"
	settings["UseSharedDeviceKeys"] = true
	settings["EnableCreateUserAtLogin"] = true
	p := platformSSOProfile(t, settings)
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		t.Fatal(err)
	}
	configuration := root["PayloadContent"].([]any)[0].(map[string]any)["PlatformSSO"].(map[string]any)
	configuration["EnableRegistrationDuringSetup"] = registration
	configuration["EnableCreateFirstUserDuringSetup"] = firstUser
	data, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestADEPlatformSSORequiresExplicitProviderAndUnattendedPolicy(t *testing.T) {
	o := adeEnrollmentOptions()
	o.AutoAdvance = true
	o.MacAdmin = &MacAdminOptions{ShortName: "managedadmin", PrimaryAccount: "skip"}
	o.RequiredApplications = []string{uuid.NewString()}
	o.PlatformSSO = &ADEPlatformSSOOptions{ProfileRevisionID: uuid.NewString(), ApplicationVersionID: o.RequiredApplications[0], ProviderConfirmed: true, ApprovalReason: "Reviewed provider extension and silent registration support"}
	if err := validateADEPlatformSSOOptions(o); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ADEProfileOptions){
		func(o *ADEProfileOptions) { o.AutoAdvance = false },
		func(o *ADEProfileOptions) { o.AwaitConfiguration = false },
		func(o *ADEProfileOptions) { o.Platform = PlatformIOS },
		func(o *ADEProfileOptions) { o.MacAdmin = nil },
		func(o *ADEProfileOptions) { o.MacAdmin.PrimaryAccount = "standard" },
		func(o *ADEProfileOptions) { o.RequiredApplications = nil },
		func(o *ADEProfileOptions) { o.PlatformSSO.ProviderConfirmed = false },
		func(o *ADEProfileOptions) { o.PlatformSSO.ApprovalReason = "" },
		func(o *ADEProfileOptions) { o.PlatformSSO.ProfileRevisionID = "invalid" },
	} {
		copy := o
		provider, admin := *o.PlatformSSO, *o.MacAdmin
		copy.PlatformSSO, copy.MacAdmin = &provider, &admin
		mutate(&copy)
		if !errors.Is(validateADEPlatformSSOOptions(copy), ErrADEPlatformSSO) {
			t.Fatal("incomplete unattended provider review accepted")
		}
	}
	for _, tc := range []struct {
		registration, first any
		valid               bool
	}{{true, false, true}, {false, false, false}, {true, true, false}, {"true", false, false}} {
		p := &Profile{Scope: "System", Payload: adeSSOPayload(t, tc.registration, tc.first)}
		if (validateADEPlatformSSOProfile(p) == nil) != tc.valid {
			t.Fatal("incorrect Setup Assistant flags accepted")
		}
	}
	if validateADEPlatformSSOProfile(platformSSOProfile(t, platformSSOSettings())) == nil {
		t.Fatal("ordinary Platform SSO defaults accepted for unattended ADE")
	}
}

type adeSSOTestDriver struct {
	t                   *testing.T
	s                   *Store
	d                   *Device
	p                   *Profile
	v                   *SoftwareVersion
	installed, awaiting bool
	wrongUUID           string
}

func (r *adeSSOTestDriver) drive(wire map[string]any, stop string) map[string]any {
	r.t.Helper()
	if wire == nil {
		wire = adeConnect(r.t, r.s, r.d, "Idle", "", nil)
	}
	for range 60 {
		if wire == nil {
			return nil
		}
		command := wire["Command"].(map[string]any)
		kind := command["RequestType"].(string)
		if kind == stop {
			return wire
		}
		fields := map[string]any{}
		switch kind {
		case "DeviceInformation":
			fields["QueryResponses"] = map[string]any{"SerialNumber": r.d.SerialNumber, "ProductName": "Mac16,1", "OSVersion": "26.0", "IsSupervised": true, "IsAppleSilicon": true, "AwaitingConfiguration": r.awaiting, "AutoSetupAdminAccounts": []any{}}
		case "SecurityInfo":
			fields["SecurityInfo"] = map[string]any{"ManagementStatus": map[string]any{"UserApprovedEnrollment": true, "IsUserEnrollment": false}}
		case "ProfileList":
			profiles := []any{}
			if r.installed {
				id := r.p.UUID
				if r.wrongUUID != "" {
					id = r.wrongUUID
				}
				profiles = append(profiles, map[string]any{"PayloadIdentifier": r.p.Identifier, "PayloadUUID": id})
			}
			fields["ProfileList"] = profiles
		case "InstallProfile":
			var root map[string]any
			if _, err := plist.Unmarshal(command["Payload"].([]byte), &root); err != nil || root["PayloadUUID"] != r.p.UUID {
				r.t.Fatal("ADE installed an unbound profile revision", err)
			}
			r.installed = true
		case "AccountConfiguration":
			if command["SkipPrimarySetupAccountCreation"] != true || len(command["AutoSetupAdminAccounts"].([]any)) != 1 {
				r.t.Fatal("ADE did not skip primary account creation with a managed administrator")
			}
		case "InstallEnterpriseApplication":
		case "ManagedApplicationList":
			fields["ManagedApplicationList"] = map[string]any{r.v.Identifier: map[string]any{"Status": "Managed"}}
		case "InstalledApplicationList":
			fields["InstalledApplicationList"] = []any{map[string]any{"Identifier": r.v.Identifier, "Version": r.v.Version}}
		case "AvailableOSUpdates":
			fields["AvailableOSUpdates"] = []any{}
		case "DeclarativeManagement":
		case "DeviceConfigured":
			r.t.Fatal("setup released without the expected stop")
		default:
			r.t.Fatal("unexpected synthetic ADE command", kind)
		}
		wire = adeConnect(r.t, r.s, r.d, "Acknowledged", wire["CommandUUID"].(string), fields)
	}
	r.t.Fatal("synthetic ADE provider workflow did not settle")
	return nil
}

func TestADEPlatformSSORetainsProfileAndAppUntilObservedSetupExit(t *testing.T) {
	s, server, remote := adeEnrollmentStore(t)
	v, err := s.publishMacAppPackage(t.Context(), Scope{TenantID: 1}, testMacAppPackage(), "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	data := adeSSOPayload(t, true, false)
	first, err := s.SaveProfile(t.Context(), 1, "", 0, data, "admin")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := revisionHistory(t, s, first.ID)[0]
	o := adeEnrollmentOptions()
	o.AutoAdvance = true
	o.MacAdmin = &MacAdminOptions{ShortName: "managedadmin", PrimaryAccount: "skip"}
	o.RequiredApplications = []string{v.ID}
	o.PlatformSSO = &ADEPlatformSSOOptions{ProfileRevisionID: snapshot.ID, ApplicationVersionID: v.ID, ProviderConfirmed: true, ApprovalReason: "Synthetic provider/app and silent registration review"}
	if _, err = s.CreateADEProfile(t.Context(), 1, server, o, "admin", nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("provider policy accepted missing transaction authority", err)
	}
	id, err := s.createADEProfile(t.Context(), 1, server, o, "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteProfile(t.Context(), 1, first.ID, "admin"); !errors.Is(err, ErrADEPlatformSSO) {
		t.Fatal("active ADE policy lost its catalog profile", err)
	}
	if err = s.publishADEProfile(t.Context(), 1, server, id); err != nil {
		t.Fatal(err)
	}
	p := adeProfileState(t, s, server, id)
	if p.PlatformSSO == nil || *p.PlatformSSO != *o.PlatformSSO {
		t.Fatal("publication lost provider review")
	}
	if _, err = s.SaveProfile(t.Context(), 1, first.ID, 1, data, "admin"); err != nil {
		t.Fatal(err)
	}
	info := &ade.MachineInfo{Serial: "SYNTHETICSSOMAC1", UDID: uuid.NewString(), Product: "Mac16,1", OSVersion: "25.0", Build: "25A1", SignerFingerprint: strings.Repeat("a", 64), SignedAt: time.Now()}
	adeAddSerial(t, s, remote, server, info.Serial)
	if err = s.setADETargets(t.Context(), 1, server, p.ID, []string{info.Serial}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.reconcileADETargetBatch(t.Context(), 1, server); err != nil {
		t.Fatal(err)
	}
	definition := remote.profiles[p.RemoteID]
	selector := definition.URL[strings.LastIndex(definition.URL, "/")+1:]
	if _, err = s.admitADE(t.Context(), selector, info); !errors.Is(err, ErrADEPlatformSSO) {
		t.Fatal("pre-26 Mac entered unattended SSO", err)
	}
	info.OSVersion = "26.0"
	profile, err := s.admitADE(t.Context(), selector, info)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := adeAuthenticate(t, s, info, profile, true)
	scope := Scope{TenantID: 1, SiteID: 1}
	driver := &adeSSOTestDriver{t: t, s: s, d: d, p: first, v: v, awaiting: true}
	wire := driver.drive(nil, "InstallProfile")
	if wire == nil {
		t.Fatal("required SSO profile was not automatically assigned")
	}
	current, err := s.SaveProfile(t.Context(), 1, first.ID, 2, data, "admin")
	if err != nil {
		t.Fatal(err)
	}
	items, err := s.Assignments(t.Context(), scope, d.ID)
	if err != nil || len(items) != 1 || items[0].Revision != 1 {
		t.Fatal("catalog update changed the held ADE requirement", err)
	}
	for _, desired := range []string{"installed", "removed"} {
		if err = s.AssignProfile(t.Context(), scope, first.ID, []string{d.ID}, desired, "admin"); !errors.Is(err, ErrADEPlatformSSO) {
			t.Fatal("ordinary assignment bypassed ADE ownership", err)
		}
	}
	driver.wrongUUID = current.UUID
	if driver.drive(wire, "") != nil || adeSetupCommand(t, s, d) != "" {
		t.Fatal("wrong profile revision released setup")
	}
	if err = s.RepairADEPlatformSSO(t.Context(), scope, d.ID, snapshot.ID, "Repair synthetic drift", "admin", nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("repair accepted missing authority", err)
	}
	if err = s.repairADEPlatformSSO(t.Context(), scope, d.ID, uuid.NewString(), "Stale requirement", "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("repair accepted stale requirement", err)
	}
	if err = s.repairADEPlatformSSO(t.Context(), scope, d.ID, snapshot.ID, "Repair synthetic drift", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_ade_sso_repairs SET reason='Changed' WHERE device_id=$1`, d.ID); err == nil {
		t.Fatal("provider repair history was mutable")
	}
	driver.wrongUUID = ""
	wire = driver.drive(nil, "DeviceConfigured")
	if wire == nil {
		t.Fatal("verified profile/app/admin prerequisites did not release setup")
	}
	if err = s.repairADEPlatformSSO(t.Context(), scope, d.ID, snapshot.ID, "After release delivery", "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("repair modified a dispatched setup release", err)
	}
	next := testMacAppPackage()
	next.Version = "43.0"
	v2, err := s.publishMacAppPackage(t.Context(), Scope{TenantID: 1}, next, "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.installMacApp(t.Context(), scope, d.ID, v2.ID, "admin", MacAppInstallOptions{}, nil); !errors.Is(err, ErrADEPlatformSSO) {
		t.Fatal("provider app version changed before setup exit", err)
	}
	r := adeRequiredApp(t, s, d)
	if err = s.changeMacApp(t.Context(), scope, d.ID, r.Assignment.ID, "remove", "admin", nil); !errors.Is(err, ErrADEPlatformSSO) {
		t.Fatal("provider app removed before setup exit", err)
	}
	wire = adeConnect(t, s, d, "Acknowledged", wire["CommandUUID"].(string), nil)
	driver.awaiting = false
	driver.drive(wire, "")
	if adeSetupState(t, s, d).SetupState != "complete" {
		t.Fatal("setup exit was not observed")
	}
	if err = s.AssignProfile(t.Context(), scope, first.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal("completed setup retained exclusive profile ownership", err)
	}
	items, err = s.Assignments(t.Context(), scope, d.ID)
	if err != nil || len(items) != 1 || items[0].Revision != current.Revision {
		t.Fatal("post-setup assignment did not use selected current catalog", err)
	}
}
