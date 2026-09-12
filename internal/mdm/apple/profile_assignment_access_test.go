package apple

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func profileAssignmentAccessFixture(t *testing.T) (*Store, *access.Store, *Profile, *Device) {
	t.Helper()
	s := testStore(t)
	testSettings(t, s, 1)
	_, err := s.db.Exec(`CREATE TABLE users(uid TEXT PRIMARY KEY); INSERT INTO users VALUES('admin'),('operator'),('viewer'),('organization')`)
	require.NoError(t, err)
	permissions, err := access.NewStore(s.db)
	require.NoError(t, err)
	require.NoError(t, permissions.Migrate(t.Context()))
	require.NoError(t, permissions.Bootstrap(t.Context(), "admin"))
	for actor, grant := range map[string]access.Grant{
		"operator":     {Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}},
		"viewer":       {Role: access.Viewer, Scope: access.Scope{TenantID: 1, SiteID: 1}},
		"organization": {Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}},
	} {
		require.NoError(t, permissions.ReplaceGrants(t.Context(), "admin", actor, 0, []access.Grant{grant}))
	}
	d, _ := testEnroll(t, s, Scope{TenantID: 1, SiteID: 1}, "Owned profile target")
	drainCommands(t, s, d, nil)
	p, err := s.SaveProfile(t.Context(), 1, "", 0, revisionWiFi(t, "Owned assigned Wi-Fi", "owned-fixture-secret"), "admin")
	require.NoError(t, err)
	return s, permissions, p, d
}

func TestProfileAssignmentCurrentAuthorityAndScope(t *testing.T) {
	s, permissions, p, d := profileAssignmentAccessFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	assign := func(actor string, scope Scope, authority *access.Store) error {
		return s.AssignProfileWithAccess(t.Context(), scope, p.ID, p.Revision, []string{d.ID}, "installed", actor, authority)
	}
	for _, actor := range []string{"viewer", "missing"} {
		require.ErrorIs(t, assign(actor, scope, permissions), access.ErrDenied)
	}
	require.ErrorIs(t, assign("admin", scope, nil), access.ErrDenied)
	require.ErrorIs(t, assign("operator", Scope{TenantID: 1}, permissions), access.ErrDenied)
	require.ErrorIs(t, assign("operator", Scope{TenantID: 2, SiteID: 2}, permissions), access.ErrDenied)
	for _, actor := range []string{"operator", "organization", "admin"} {
		require.NoError(t, assign(actor, scope, permissions))
	}
	require.NoError(t, assign("organization", Scope{TenantID: 1}, permissions))
	_, err := s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`)
	require.NoError(t, err)
	for _, scope := range []Scope{scope, {TenantID: 1}} {
		require.ErrorIs(t, assign("admin", scope, permissions), ErrNotFound)
	}
}

func TestProfileAssignmentWaitsForCurrentPermissionAndRollsBackAuditFailure(t *testing.T) {
	s, permissions, p, d := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	change, err := s.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer change.Rollback()
	_, err = change.Exec(`SELECT pg_advisory_xact_lock(684627902)`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		done <- s.AssignProfileWithAccess(ctx, scope, p.ID, p.Revision, []string{d.ID}, "installed", "operator", permissions)
	}()
	select {
	case err := <-done:
		t.Fatalf("assignment bypassed the pending permission change: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	_, err = change.Exec(`DELETE FROM uem_access_grants WHERE user_id='operator'`)
	require.NoError(t, err)
	require.NoError(t, change.Commit())
	select {
	case err := <-done:
		require.ErrorIs(t, err, access.ErrDenied)
	case <-time.After(3 * time.Second):
		t.Fatal("assignment did not finish after permission replacement")
	}
	var count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_profile_assignments WHERE profile_id=$1`, p.ID).Scan(&count))
	require.Zero(t, count)

	second, _ := testEnroll(t, s, scope, "Owned second profile target")
	drainCommands(t, s, second, nil)
	targets := []string{d.ID, second.ID}
	slices.Sort(targets)
	require.NoError(t, s.AssignProfileWithAccess(ctx, scope, p.ID, p.Revision, targets, "installed", "admin", permissions))
	// Reject the last device's audit after earlier device work has been staged.
	_, err = s.db.Exec(`CREATE TABLE owned_profile_audit_rejection(resource TEXT); CREATE FUNCTION owned_profile_assignment_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='apple.profile.removed' AND EXISTS(SELECT 1 FROM owned_profile_audit_rejection WHERE resource=NEW.resource_id) THEN RAISE EXCEPTION 'owned profile assignment audit failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER owned_profile_assignment_audit_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_profile_assignment_audit_failure()`)
	require.NoError(t, err)
	_, err = s.db.Exec(`INSERT INTO owned_profile_audit_rejection VALUES($1)`, p.ID+"/"+targets[1])
	require.NoError(t, err)
	err = s.AssignProfileWithAccess(ctx, scope, p.ID, p.Revision, targets, "removed", "admin", permissions)
	require.Error(t, err)
	require.False(t, errors.Is(err, access.ErrDenied))
	for _, target := range targets {
		assignments, err := s.Assignments(ctx, scope, target)
		require.NoError(t, err)
		require.Len(t, assignments, 1)
		require.Equal(t, "installed", assignments[0].Desired)
	}
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1 AND status='queued' AND request_type='InstallProfile'`, p.ID).Scan(&count))
	require.Equal(t, 2, count)
}

func TestProfileAssignmentRechecksSiteMoveBeforeAdmission(t *testing.T) {
	s, permissions, p, d := profileAssignmentAccessFixture(t)
	change, err := s.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer change.Rollback()
	_, err = change.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		done <- s.AssignProfileWithAccess(t.Context(), Scope{TenantID: 1}, p.ID, p.Revision, []string{d.ID}, "installed", "admin", permissions)
	}()
	select {
	case err := <-done:
		t.Fatalf("assignment bypassed the pending site move: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	require.NoError(t, change.Commit())
	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrNotFound)
	case <-time.After(3 * time.Second):
		t.Fatal("assignment did not finish after the site move")
	}
	var count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&count))
	require.Zero(t, count)
}

func TestProfileAssignmentRejectsChangedReviewedRevision(t *testing.T) {
	s, permissions, p, d := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	current, err := s.SaveProfile(ctx, 1, p.ID, p.Revision, revisionWiFi(t, "Revised owned Wi-Fi", "owned-revised-secret"), "admin")
	require.NoError(t, err)
	for _, desired := range []string{"installed", "removed"} {
		require.ErrorIs(t, s.AssignProfileWithAccess(ctx, scope, p.ID, p.Revision, []string{d.ID}, desired, "operator", permissions), ErrConflict)
	}
	require.ErrorIs(t, s.AssignProfileWithAccess(ctx, scope, p.ID, 0, []string{d.ID}, "installed", "operator", permissions), ErrProfileRevision)
	var count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, s.AssignProfileWithAccess(ctx, scope, p.ID, current.Revision, []string{d.ID}, "installed", "operator", permissions))
	assignments, err := s.Assignments(ctx, scope, d.ID)
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	require.Equal(t, current.Revision, assignments[0].Revision)
}
