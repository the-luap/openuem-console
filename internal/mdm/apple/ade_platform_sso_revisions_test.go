package apple

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/ade"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func adeSSOCorrectionFixture(t *testing.T) (*Store, *Device, *Profile, *SoftwareVersion) {
	t.Helper()
	s, server, remote := adeEnrollmentStore(t)
	v, err := s.publishMacAppPackage(t.Context(), Scope{TenantID: 1}, testMacAppPackage(), "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.SaveProfile(t.Context(), 1, "", 0, adeSSOPayload(t, true, false), "admin")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := revisionHistory(t, s, p.ID)[0]
	o := adeEnrollmentOptions()
	o.AutoAdvance = true
	o.MacAdmin = &MacAdminOptions{ShortName: "managedadmin", PrimaryAccount: "skip"}
	o.RequiredApplications = []string{v.ID}
	o.PlatformSSO = &ADEPlatformSSOOptions{ProfileRevisionID: snapshot.ID, ApplicationVersionID: v.ID, ProviderConfirmed: true, ApprovalReason: "Original synthetic provider review"}
	id, err := s.createADEProfile(t.Context(), 1, server, o, "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.publishADEProfile(t.Context(), 1, server, id); err != nil {
		t.Fatal(err)
	}
	policy := adeProfileState(t, s, server, id)
	info := &ade.MachineInfo{Serial: "SYNTHETICCORRECT1", UDID: uuid.NewString(), Product: "Mac16,1", OSVersion: "26.0", Build: "26A1", SignerFingerprint: strings.Repeat("a", 64), SignedAt: time.Now()}
	adeAddSerial(t, s, remote, server, info.Serial)
	if err = s.setADETargets(t.Context(), 1, server, id, []string{info.Serial}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.reconcileADETargetBatch(t.Context(), 1, server); err != nil {
		t.Fatal(err)
	}
	callback := remote.profiles[policy.RemoteID].URL
	data, err := s.admitADE(t.Context(), callback[strings.LastIndex(callback, "/")+1:], info)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := adeAuthenticate(t, s, info, data, true)
	return s, d, p, v
}

func TestADEPlatformSSORevisionHistoryAndRetainedChoicePagination(t *testing.T) {
	s, d, p, v := adeSSOCorrectionFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	driver := &adeSSOTestDriver{t: t, s: s, d: d, p: p, v: v, awaiting: true, wrongUUID: uuid.NewString()}
	if driver.drive(nil, "InstallEnterpriseApplication") == nil {
		t.Fatal("missing held provider installer")
	}
	original := revisionHistory(t, s, p.ID)[0].ID
	if _, err := s.SaveProfile(t.Context(), 1, p.ID, 1, p.Payload, "admin"); err != nil {
		t.Fatal(err)
	}
	second := revisionHistory(t, s, p.ID)[0].ID
	initial, err := s.ADEPlatformSSOStatus(t.Context(), scope, d.ID)
	if err != nil || initial == nil {
		t.Fatal(err)
	}
	current := initial
	for i := range 100 {
		selected := second
		if i%2 == 1 {
			selected = original
		}
		o := ADEPlatformSSOCorrection{ExpectedRevisionID: current.BindingRevisionID, ProfileRevisionID: selected, ApplicationVersionID: v.ID, ProviderConfirmed: true, Reason: "Synthetic repeated review"}
		if err = s.correctADEPlatformSSO(t.Context(), scope, d.ID, o, "admin", nil); err != nil {
			t.Fatal("profile-only correction failed", i, err)
		}
		current, err = s.ADEPlatformSSOStatus(t.Context(), scope, d.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if current.ProfileRevisionID != initial.ProfileRevisionID || current.ApplicationVersionID != initial.ApplicationVersionID || current.BindingRevisionID == initial.BindingRevisionID {
		t.Fatal("returning to a prior pair reused its concurrency identity")
	}
	if err = s.repairADEPlatformSSO(t.Context(), scope, d.ID, initial.BindingRevisionID, "Stale original form", "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("stale repair survived a return to the original pair", err)
	}
	_, items, next, err := s.ADEPlatformSSORevisions(t.Context(), scope, d.ID, "")
	if err != nil || len(items) != 100 || next == "" || items[0].ID != current.BindingRevisionID {
		t.Fatal("provider history first page incorrect", err)
	}
	_, last, end, err := s.ADEPlatformSSORevisions(t.Context(), scope, d.ID, next)
	if err != nil || len(last) != 1 || end != "" || last[0].PreviousID != "" || last[0].ID == items[99].ID {
		t.Fatal("provider history omitted or repeated original review", err)
	}
	if _, _, _, err = s.ADEPlatformSSORevisions(t.Context(), scope, d.ID, uuid.NewString()); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign provider history cursor accepted", err)
	}
	for revision := 2; revision < 28; revision++ {
		if _, err = s.SaveProfile(t.Context(), 1, p.ID, revision, p.Payload, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	choices, after, err := s.ADEPlatformSSORevisionChoices(t.Context(), scope, d.ID, "", "")
	if err != nil || len(choices) != 25 || after == "" {
		t.Fatal("retained profile choices unbounded", err)
	}
	older, after, err := s.ADEPlatformSSORevisionChoices(t.Context(), scope, d.ID, "", after)
	if err != nil || len(older) != 3 || after != "" || older[0].ID == choices[24].ID {
		t.Fatal("retained choice cursor skipped or repeated revisions", err)
	}
	for _, query := range []string{"%", "_", "\\"} {
		items, _, err := s.ADEPlatformSSORevisionChoices(t.Context(), scope, d.ID, query, "")
		if err != nil || len(items) != 0 {
			t.Fatal("retained search interpreted literal wildcard", err)
		}
	}
}

func TestADEPlatformSSORevisionMigrationPreservesExistingReviewsAndRepairs(t *testing.T) {
	s := testStoreBeforeMigration(t, "migrations/032_ade_sso_revisions.sql")
	data, err := os.ReadFile("testdata/ade_sso_legacy.sql")
	if err != nil {
		t.Fatal(err)
	}
	adeExec(t, s, string(data))
	adeExec(t, s, "INSERT INTO mdm_apple_ade_sso_repairs(id,tenant_id,device_id,requirement_id,profile_revision_id,actor,reason) VALUES('00000000-0000-4000-8000-000000000039',1,'00000000-0000-4000-8000-000000000020','00000000-0000-4000-8000-000000000023','00000000-0000-4000-8000-000000000003','Original actor','Original receipt')")
	var before, after, binding string
	if err = s.db.QueryRow("SELECT to_jsonb(h)::text FROM mdm_apple_ade_sso_repairs h").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal("migration was not repeatable", err)
	}
	if err = s.db.QueryRow("SELECT (to_jsonb(h)-'binding_revision_id')::text,binding_revision_id FROM mdm_apple_ade_sso_repairs h").Scan(&after, &binding); err != nil || before != after || binding != "00000000-0000-4000-8000-000000000023" {
		t.Fatal("migration changed the historical receipt", err)
	}
	r, history, _, err := s.ADEPlatformSSORevisions(t.Context(), Scope{TenantID: 1, SiteID: 1}, "00000000-0000-4000-8000-000000000020", "")
	if err != nil || r == nil || len(history) != 1 || r.BindingRevisionID != binding || history[0].PreviousID != "" || history[0].Reason != "Synthetic review" || history[0].ProfileRevisionID != r.ProfileRevisionID {
		t.Fatal("migration invented or changed a provider review", err)
	}
	for _, q := range []string{"UPDATE mdm_apple_ade_sso_revisions SET reason='Changed'", "UPDATE mdm_apple_ade_sso_repairs SET reason='Changed'", "DELETE FROM mdm_apple_ade_sso_revisions"} {
		if _, err = s.db.Exec(q); err == nil {
			t.Fatal("migration left retained history mutable")
		}
	}
}

func TestADEPlatformSSOCorrectionAtomicPairConcurrencyAndFreshVerification(t *testing.T) {
	s, d, p, v := adeSSOCorrectionFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	driver := &adeSSOTestDriver{t: t, s: s, d: d, p: p, v: v, awaiting: true, wrongUUID: uuid.NewString()}
	wire := driver.drive(nil, "InstallEnterpriseApplication")
	if wire == nil {
		t.Fatal("provider installer was not sent")
	}
	next, err := s.SaveProfile(t.Context(), 1, p.ID, 1, p.Payload, "admin")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := revisionHistory(t, s, p.ID)[0]
	app := testMacAppPackage()
	app.Version = "43.0"
	v2, err := s.publishMacAppPackage(t.Context(), Scope{TenantID: 1}, app, "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	status, err := s.ADEPlatformSSOStatus(t.Context(), scope, d.ID)
	if err != nil || status == nil {
		t.Fatal(err)
	}
	original := status.BindingRevisionID
	o := ADEPlatformSSOCorrection{ExpectedRevisionID: original, ProfileRevisionID: snapshot.ID, ApplicationVersionID: v2.ID, ProviderConfirmed: true, Reason: "Correct <provider> pair"}
	if err = s.CorrectADEPlatformSSO(t.Context(), scope, d.ID, o, "admin", nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("correction accepted missing authority", err)
	}
	if err = s.correctADEPlatformSSO(t.Context(), scope, d.ID, o, "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("unresolved installer was overwritten", err)
	}
	current, history, _, err := s.ADEPlatformSSORevisions(t.Context(), scope, d.ID, "")
	if err != nil || len(history) != 1 || current.BindingRevisionID != original || adeRequiredApp(t, s, d).Version.ID != v.ID {
		t.Fatal("failed pair correction leaked a revision", err)
	}
	if driver.drive(wire, "") != nil {
		t.Fatal("missing original profile released setup")
	}
	for i, minimum := range []string{"99.0", "14.0"} {
		input := testMacAppPackage()
		input.Version = []string{"44.0", "45.0"}[i]
		input.MinimumOS = minimum
		unavailable, err := s.publishMacAppPackage(t.Context(), Scope{TenantID: 1}, input, "admin", nil)
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			adeExec(t, s, "UPDATE uem_software_versions SET withdrawn_at=clock_timestamp() WHERE id=$1", unavailable.ID)
		}
		copy := o
		copy.ApplicationVersionID = unavailable.ID
		if err = s.correctADEPlatformSSO(t.Context(), scope, d.ID, copy, "admin", nil); err == nil {
			t.Fatal("incompatible or withdrawn provider app accepted")
		}
	}
	for _, change := range []func(*ADEPlatformSSOCorrection){
		func(o *ADEPlatformSSOCorrection) { o.ExpectedRevisionID = uuid.NewString() },
		func(o *ADEPlatformSSOCorrection) { o.ProviderConfirmed = false },
		func(o *ADEPlatformSSOCorrection) { o.Reason = "" },
		func(o *ADEPlatformSSOCorrection) { o.ProfileRevisionID = uuid.NewString() },
		func(o *ADEPlatformSSOCorrection) { o.ApplicationVersionID = uuid.NewString() },
	} {
		copy := o
		change(&copy)
		if err = s.correctADEPlatformSSO(t.Context(), scope, d.ID, copy, "admin", nil); err == nil {
			t.Fatal("invalid reviewed pair accepted")
		}
	}
	choices, more, err := s.ADEPlatformSSORevisionChoices(t.Context(), scope, d.ID, "", "")
	if err != nil || len(choices) != 2 || more != "" || choices[0].ID != snapshot.ID || !choices[0].Eligible {
		t.Fatal("retained profile choices lost revisions", err)
	}
	if _, _, err = s.ADEPlatformSSORevisionChoices(t.Context(), scope, d.ID, "", uuid.NewString()); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign profile cursor accepted", err)
	}
	for _, foreign := range []Scope{{TenantID: 2, SiteID: 2}, {TenantID: 1, SiteID: 2}} {
		if err = s.correctADEPlatformSSO(t.Context(), foreign, d.ID, o, "admin", nil); !errors.Is(err, ErrNotFound) {
			t.Fatal("correction crossed scope", err)
		}
		if _, _, _, err = s.ADEPlatformSSORevisions(t.Context(), foreign, d.ID, ""); !errors.Is(err, ErrNotFound) {
			t.Fatal("pair history crossed scope", err)
		}
	}
	adeExec(t, s, `CREATE FUNCTION reject_sso_correction_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.ade.platform_sso.correct' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_sso_correction_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_sso_correction_audit()`)
	if err = s.correctADEPlatformSSO(t.Context(), scope, d.ID, o, "admin", nil); err == nil {
		t.Fatal("correction committed without its audit")
	}
	adeExec(t, s, `DROP TRIGGER reject_sso_correction_audit ON mdm_apple_audit; DROP FUNCTION reject_sso_correction_audit()`)
	current, history, _, err = s.ADEPlatformSSORevisions(t.Context(), scope, d.ID, "")
	if err != nil || len(history) != 1 || current.BindingRevisionID != original || adeRequiredApp(t, s, d).Version.ID != v.ID {
		t.Fatal("audit failure leaked provider or app changes", err)
	}
	results := make(chan error, 2)
	start := make(chan struct{})
	for range 2 {
		go func() { <-start; results <- s.correctADEPlatformSSO(t.Context(), scope, d.ID, o, "admin", nil) }()
	}
	close(start)
	accepted, conflicts := 0, 0
	for range 2 {
		err = <-results
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || conflicts != 1 {
		t.Fatal("concurrent pair corrections were not serialized")
	}
	current, history, more, err = s.ADEPlatformSSORevisions(t.Context(), scope, d.ID, "")
	if err != nil || len(history) != 2 || more != "" || current.ProfileRevisionID != snapshot.ID || current.ApplicationVersionID != v2.ID || history[0].PreviousID != original || history[1].PreviousID != "" {
		t.Fatal("pair history lost original or correction", err)
	}
	encoded, _ := json.Marshal(history)
	if strings.Contains(string(encoded), "synthetic-provider-token") {
		t.Fatal("pair history exposed provider credentials")
	}
	appRequirement := adeRequiredApp(t, s, d)
	if !appRequirement.PlatformSSO || appRequirement.Version.ID != v2.ID || appRequirement.OriginalVersionID != v.ID {
		t.Fatal("paired app correction rewrote original intent")
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_ade_sso_revisions SET reason='Changed' WHERE id=$1`, current.BindingRevisionID); err == nil {
		t.Fatal("pair review history was mutable")
	}
	if err = s.repairADEPlatformSSO(t.Context(), scope, d.ID, original, "Stale pair repair", "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("old repair form bypassed the reviewed pair", err)
	}
	driver.p, driver.v, driver.wrongUUID = next, v2, p.UUID
	if driver.drive(nil, "") != nil || adeSetupCommand(t, s, d) != "" {
		t.Fatal("old profile observation verified the corrected pair")
	}
	if err = s.repairADEPlatformSSO(t.Context(), scope, d.ID, current.BindingRevisionID, "Resend corrected profile", "admin", nil); err != nil {
		t.Fatal(err)
	}
	_, repairs, _, err := s.ADEPlatformSSORepairs(t.Context(), scope, d.ID, "")
	if err != nil || len(repairs) != 1 || repairs[0].ProfileRevisionID != snapshot.ID {
		t.Fatal("repair did not retain corrected snapshot", err)
	}
	driver.wrongUUID = ""
	wire = driver.drive(nil, "DeviceConfigured")
	if wire == nil {
		t.Fatal("corrected profile and app observations did not release setup")
	}
	o.ExpectedRevisionID = current.BindingRevisionID
	o.ProfileRevisionID = history[1].ProfileRevisionID
	if err = s.correctADEPlatformSSO(t.Context(), scope, d.ID, o, "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("dispatched release accepted provider correction", err)
	}
	wire = adeConnect(t, s, d, "Acknowledged", wire["CommandUUID"].(string), nil)
	driver.awaiting = false
	driver.drive(wire, "")
	if adeSetupState(t, s, d).SetupState != "complete" {
		t.Fatal("corrected setup did not finish")
	}
}
