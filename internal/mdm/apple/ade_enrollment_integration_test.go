package apple

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/ade"
)

type adeEnrollmentFixture struct {
	*adeFixtureService
	mu                       sync.Mutex
	profiles                 map[string]ade.EnrollmentProfile
	details                  map[string]ade.DeviceDetail
	definitions, assignments int
	define                   func(context.Context, ade.EnrollmentProfile) (string, error)
	change                   func([]string) (ade.AssignmentResult, error)
}

func (f *adeEnrollmentFixture) DefineProfile(ctx context.Context, p ade.EnrollmentProfile) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.definitions++
	if f.define != nil {
		return f.define(ctx, p)
	}
	id := "REMOTE" + strings.ReplaceAll(uuid.NewString(), "-", "")
	f.profiles[id] = p
	return id, nil
}
func (f *adeEnrollmentFixture) Profile(_ context.Context, id string) (ade.EnrollmentProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.profiles[id]
	if !ok {
		return p, ade.ErrService
	}
	return p, nil
}
func (f *adeEnrollmentFixture) DeviceDetails(_ context.Context, serials []string) (map[string]ade.DeviceDetail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]ade.DeviceDetail{}
	for _, serial := range serials {
		if d, ok := f.details[serial]; ok {
			out[serial] = d
		}
	}
	return out, nil
}
func (f *adeEnrollmentFixture) AssignProfile(_ context.Context, id string, serials []string) (ade.AssignmentResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assignments++
	if f.change != nil {
		return f.change(serials)
	}
	r := ade.AssignmentResult{Devices: map[string]string{}}
	for _, serial := range serials {
		d := f.details[serial]
		d.ProfileID = id
		d.ProfileStatus = "assigned"
		f.details[serial] = d
		r.Devices[serial] = "SUCCESS"
	}
	return r, nil
}
func (f *adeEnrollmentFixture) ClearProfile(ctx context.Context, serials []string) (ade.AssignmentResult, error) {
	return f.AssignProfile(ctx, "", serials)
}

func adeEnrollmentStore(t *testing.T) (*Store, string, *adeEnrollmentFixture) {
	t.Helper()
	s, server, base := adeFixture(t)
	testSettings(t, s, 1)
	f := &adeEnrollmentFixture{adeFixtureService: base, profiles: map[string]ade.EnrollmentProfile{}, details: map[string]ade.DeviceDetail{}}
	s.adeService = func(*ade.Token) ade.Service { return f }
	return s, server, f
}

func adeEnrollmentOptions() ADEProfileOptions {
	return ADEProfileOptions{SiteID: 1, Platform: PlatformMacOS, Name: "Synthetic ADE Mac", AwaitConfiguration: true, AllowDeviceLock: true, IgnoreBackupProfile: true, SkipSetupItems: []string{"Siri"}}
}
func adeCreateProfile(t *testing.T, s *Store, server string) string {
	t.Helper()
	id, err := s.createADEProfile(t.Context(), 1, server, adeEnrollmentOptions(), "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func adeProfileState(t *testing.T, s *Store, server, id string) ADEEnrollmentProfile {
	t.Helper()
	list, err := s.ADEProfiles(t.Context(), 1, server)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range list {
		if p.ID == id {
			return p
		}
	}
	t.Fatal("ADE profile missing")
	return ADEEnrollmentProfile{}
}
func adeProfilePublished(t *testing.T, s *Store, server string) ADEEnrollmentProfile {
	t.Helper()
	id := adeCreateProfile(t, s, server)
	if err := s.publishADEProfile(t.Context(), 1, server, id); err != nil {
		t.Fatal(err)
	}
	p := adeProfileState(t, s, server, id)
	if p.Status != "published" || p.RemoteID == "" {
		t.Fatal("profile not published", p.Status, p.Error)
	}
	return p
}
func adeAddSerial(t *testing.T, s *Store, f *adeEnrollmentFixture, server, serial string) {
	t.Helper()
	adeExec(t, s, `INSERT INTO mdm_apple_ade_devices(tenant_id,server_id,serial,assigned,payload) VALUES(1,$1,$2,true,'{}')`, server, serial)
	f.details[serial] = ade.DeviceDetail{Device: ade.Device{Serial: serial, Family: "Mac"}, ResponseStatus: "SUCCESS"}
}
func adeTargetState(t *testing.T, s *Store, server, serial string) ADETarget {
	t.Helper()
	list, _, err := s.ADETargets(t.Context(), 1, server, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range list {
		if v.Serial == serial {
			return v
		}
	}
	t.Fatal("ADE target missing")
	return ADETarget{}
}
func adeTargetsDue(t *testing.T, s *Store, server string) {
	t.Helper()
	adeExec(t, s, `UPDATE mdm_apple_ade_targets SET next_attempt_at=clock_timestamp()-interval '1 second',retry_after=NULL WHERE server_id=$1`, server)
}

func TestADEProfileDurablePublicationScopeAndSecrets(t *testing.T) {
	s, server, f := adeEnrollmentStore(t)
	id := adeCreateProfile(t, s, server)
	if f.definitions != 0 {
		t.Fatal("creation bypassed durable worker intent")
	}
	f.define = func(_ context.Context, p ade.EnrollmentProfile) (string, error) {
		var status string
		if err := s.db.QueryRow(`SELECT status FROM mdm_apple_ade_profiles WHERE id=$1`, id).Scan(&status); err != nil || status != "publishing" {
			t.Fatal("remote call preceded committed intent", status, err)
		}
		if !p.Supervised || !p.Mandatory || p.Removable || !p.AwaitDeviceConfigured || !strings.HasPrefix(p.URL, "https://mdm.example.test/mdm/apple/ade/") {
			t.Fatal("definition lost enrollment requirements")
		}
		f.profiles["REMOTE1"] = p
		return "REMOTE1", nil
	}
	if err := s.publishADEProfile(t.Context(), 1, server, id); err != nil {
		t.Fatal(err)
	}
	p := adeProfileState(t, s, server, id)
	if p.Status != "published" || p.RemoteID != "REMOTE1" || !p.DeviceLockAllowed {
		t.Fatal("publication missing")
	}
	if err := s.publishADEProfile(t.Context(), 1, server, id); err != nil || f.definitions != 1 {
		t.Fatal("published profile duplicated", err)
	}
	var sealed []byte
	if err := s.db.QueryRow(`SELECT definition FROM mdm_apple_ade_profiles WHERE id=$1`, id).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "mdm.example.test") || strings.Contains(fmt.Sprintf("%+v", p), "/mdm/apple/ade/") {
		t.Fatal("profile selector exposed")
	}
	for _, q := range []string{`UPDATE mdm_apple_ade_profiles SET site_id=2 WHERE id=$1`, `UPDATE mdm_apple_ade_profiles SET platform='ios' WHERE id=$1`, `UPDATE mdm_apple_ade_profiles SET removable=true WHERE id=$1`, `UPDATE mdm_apple_ade_profiles SET remote_id='OTHER1' WHERE id=$1`} {
		if _, err := s.db.Exec(q, id); err == nil {
			t.Fatal("immutable ADE scope/options changed")
		}
	}
	foreign := adeEnrollmentOptions()
	foreign.SiteID = 2
	if _, err := s.createADEProfile(t.Context(), 1, server, foreign, "admin", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign site accepted", err)
	}
	denied := func(context.Context, *sql.Tx) error { return errors.New("revoked test permission") }
	if _, err := s.createADEProfile(t.Context(), 1, server, adeEnrollmentOptions(), "admin", denied); err == nil {
		t.Fatal("transaction authorization ignored")
	}
	if _, err := s.CreateADEProfile(t.Context(), 1, server, adeEnrollmentOptions(), "admin", nil); err == nil {
		t.Fatal("missing permission store accepted")
	}
	for _, scope := range []Scope{{TenantID: 1}, {TenantID: 1, SiteID: 1}} {
		used, err := s.ScopeInUse(t.Context(), scope)
		if err != nil || !used {
			t.Fatal("ADE scope deletion not protected", err)
		}
	}
	c, err := s.Settings(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	c.PublicURL = "https://changed.example.test"
	if err = s.Configure(t.Context(), *c, "admin"); err == nil {
		t.Fatal("published callback origin changed")
	}
}

func TestADEPublicationUnknownRecoveryAndAuditRollback(t *testing.T) {
	s, server, f := adeEnrollmentStore(t)
	id := adeCreateProfile(t, s, server)
	f.define = func(context.Context, ade.EnrollmentProfile) (string, error) { return "", ade.ErrService }
	if err := s.publishADEProfile(t.Context(), 1, server, id); err != nil {
		t.Fatal(err)
	}
	if p := adeProfileState(t, s, server, id); p.Status != "unknown" || p.RemoteID != "" {
		t.Fatal("uncertain creation became success", p.Status)
	}
	if err := s.publishADEProfile(t.Context(), 1, server, id); err != nil || f.definitions != 1 {
		t.Fatal("uncertain creation automatically repeated", err)
	}
	if err := s.changeADEProfile(t.Context(), 1, server, id, "retry", "admin", nil); err != nil {
		t.Fatal(err)
	}
	f.define = nil
	adeExec(t, s, `CREATE FUNCTION reject_ade_publication_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.ade.profile.publish' THEN RAISE EXCEPTION 'synthetic audit rejection'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_ade_publication_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_ade_publication_audit()`)
	if err := s.publishADEProfile(t.Context(), 1, server, id); err == nil {
		t.Fatal("publication survived missing audit")
	}
	if p := adeProfileState(t, s, server, id); p.Status != "publishing" || p.RemoteID != "" {
		t.Fatal("lost commit did not preserve pre-call intent")
	}
	adeExec(t, s, `UPDATE mdm_apple_ade_profiles SET attempted_at=clock_timestamp()-interval '3 minutes' WHERE id=$1`, id)
	if err := s.publishADEProfile(t.Context(), 1, server, id); err != nil {
		t.Fatal(err)
	}
	if p := adeProfileState(t, s, server, id); p.Status != "unknown" || p.Error != "publication_interrupted" || f.definitions != 2 {
		t.Fatal("crash recovery retransmitted creation", p.Status, p.Error)
	}
}

func TestADETargetReconciliationPreservesIntentAndThrottle(t *testing.T) {
	s, server, f := adeEnrollmentStore(t)
	p := adeProfilePublished(t, s, server)
	for _, serial := range []string{"SYNTHETIC123", "SYNTHETIC124"} {
		adeAddSerial(t, s, f, server, serial)
	}
	if err := s.setADETargets(t.Context(), 1, server, p.ID, []string{"SYNTHETIC123", "SYNTHETIC124"}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	if f.assignments != 0 {
		t.Fatal("operator transaction called Apple directly")
	}
	f.change = func([]string) (ade.AssignmentResult, error) {
		return ade.AssignmentResult{Devices: map[string]string{"SYNTHETIC123": "SUCCESS", "SYNTHETIC124": "THROTTLED"}, RetryAfter: time.Hour}, nil
	}
	if err := s.reconcileADETargetBatch(t.Context(), 1, server); err != nil {
		t.Fatal(err)
	}
	a, b := adeTargetState(t, s, server, "SYNTHETIC123"), adeTargetState(t, s, server, "SYNTHETIC124")
	if a.Status != "accepted" || b.Status != "throttled" || b.NextAttemptAt.Before(time.Now().Add(59*time.Minute)) {
		t.Fatal("assignment response lost")
	}
	deadline := b.NextAttemptAt
	for range 2 {
		if err := s.setADETargets(t.Context(), 1, server, p.ID, []string{"SYNTHETIC124"}, "admin", nil); err != nil {
			t.Fatal(err)
		}
	}
	b = adeTargetState(t, s, server, "SYNTHETIC124")
	if b.NextAttemptAt.Before(deadline) {
		t.Fatal("repeated operator action bypassed Apple cooldown")
	}
	if err := s.changeADEProfile(t.Context(), 1, server, p.ID, "disable", "admin", nil); !errors.Is(err, ErrADEProfile) {
		t.Fatal("in-use profile disabled", err)
	}
	f.change = nil
	adeTargetsDue(t, s, server)
	if err := s.reconcileADETargetBatch(t.Context(), 1, server); err != nil {
		t.Fatal(err)
	}
	adeTargetsDue(t, s, server)
	if err := s.reconcileADETargetBatch(t.Context(), 1, server); err != nil {
		t.Fatal(err)
	}
	a = adeTargetState(t, s, server, "SYNTHETIC123")
	if a.Status != "observed" || a.RemoteProfileID != p.RemoteID || a.DeviceID != "" {
		t.Fatal("assignment observation became a device enrollment")
	}
	if err := s.setADETargets(t.Context(), 1, server, "", []string{"SYNTHETIC123", "SYNTHETIC124"}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.reconcileADETargetBatch(t.Context(), 1, server); err != nil {
		t.Fatal(err)
	}
	if err := s.changeADEProfile(t.Context(), 1, server, p.ID, "disable", "admin", nil); err != nil {
		t.Fatal(err)
	}
}

func TestADETargetForeignMissingAndFailedOwnership(t *testing.T) {
	s, server, f := adeEnrollmentStore(t)
	p := adeProfilePublished(t, s, server)
	adeAddSerial(t, s, f, server, "SYNTHETIC123")
	for _, serials := range [][]string{{"MISSING123"}, {"SYNTHETIC123", "SYNTHETIC123"}, nil} {
		if err := s.setADETargets(t.Context(), 1, server, p.ID, serials, "admin", nil); err == nil {
			t.Fatal("invalid targets accepted")
		}
	}
	if err := s.setADETargets(t.Context(), 2, server, p.ID, []string{"SYNTHETIC123"}, "admin", nil); err == nil {
		t.Fatal("foreign connection accepted")
	}
	if err := s.setADETargets(t.Context(), 1, server, p.ID, []string{"SYNTHETIC123"}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	delete(f.details, "SYNTHETIC123")
	if err := s.reconcileADETargetBatch(t.Context(), 1, server); err != nil {
		t.Fatal(err)
	}
	if f.assignments != 0 || adeTargetState(t, s, server, "SYNTHETIC123").Status != "unavailable" {
		t.Fatal("missing Apple ownership authorized mutation")
	}
}
