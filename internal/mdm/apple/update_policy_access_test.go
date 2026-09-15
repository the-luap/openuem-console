package apple

import (
	"slices"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestUpdatePolicyCurrentAuthorityAndScope(t *testing.T) {
	s, permissions, _, d := profileAssignmentAccessFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	p := &UpdatePolicy{TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: "2026-10-01T18:00:00"}
	apply := func(actor string, scope Scope, authority *access.Store) error {
		return s.SetUpdatePolicyWithAccess(t.Context(), scope, []string{d.ID}, p, actor, authority)
	}
	for _, actor := range []string{"viewer", "missing"} {
		require.ErrorIs(t, apply(actor, scope, permissions), access.ErrDenied)
	}
	require.ErrorIs(t, apply("admin", scope, nil), access.ErrDenied)
	require.ErrorIs(t, apply("operator", Scope{TenantID: 1}, permissions), access.ErrDenied)
	require.ErrorIs(t, apply("operator", Scope{TenantID: 2, SiteID: 2}, permissions), access.ErrDenied)
	require.Error(t, s.SetUpdatePolicyWithAccess(t.Context(), scope, []string{d.ID, d.ID}, p, "admin", permissions))
	require.Error(t, s.SetUpdatePolicyWithAccess(t.Context(), scope, []string{"not-a-device"}, p, "admin", permissions))
	for _, actor := range []string{"operator", "organization", "admin"} {
		require.NoError(t, apply(actor, scope, permissions))
	}
	require.NoError(t, apply("organization", Scope{TenantID: 1}, permissions))
	require.ErrorIs(t, s.SetUpdatePolicyWithAccess(t.Context(), scope, []string{d.ID}, nil, "viewer", permissions), access.ErrDenied)
	require.NoError(t, s.SetUpdatePolicyWithAccess(t.Context(), scope, []string{d.ID}, nil, "operator", permissions))
	_, err := s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`)
	require.NoError(t, err)
	for _, targetScope := range []Scope{scope, {TenantID: 1}} {
		require.ErrorIs(t, apply("admin", targetScope, permissions), ErrNotFound)
		require.ErrorIs(t, s.SetUpdatePolicyWithAccess(t.Context(), targetScope, []string{d.ID}, nil, "admin", permissions), ErrNotFound)
	}
}

func TestUpdatePolicyPendingAuthorityChangesBlockAdmission(t *testing.T) {
	for _, changeKind := range []string{"permission", "site"} {
		t.Run(changeKind, func(t *testing.T) {
			s, permissions, _, d := profileAssignmentAccessFixture(t)
			change, err := s.db.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer change.Rollback()
			actor := "operator"
			if changeKind == "permission" {
				_, err = change.Exec(`SELECT pg_advisory_xact_lock(684627902); DELETE FROM uem_access_grants WHERE user_id='operator'`)
			} else {
				actor = "admin"
				_, err = change.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`)
			}
			require.NoError(t, err)
			p := &UpdatePolicy{TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: "2026-10-01T18:00:00"}
			done := make(chan error, 1)
			go func() {
				done <- s.SetUpdatePolicyWithAccess(t.Context(), Scope{TenantID: 1, SiteID: 1}, []string{d.ID}, p, actor, permissions)
			}()
			select {
			case err := <-done:
				t.Fatalf("update bypassed pending authority change: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			require.NoError(t, change.Commit())
			select {
			case err := <-done:
				if changeKind == "permission" {
					require.ErrorIs(t, err, access.ErrDenied)
				} else {
					require.ErrorIs(t, err, ErrNotFound)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("update did not finish after authority change")
			}
			var count int
			require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_policies`).Scan(&count))
			require.Zero(t, count)
			require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE request_type='DeclarativeManagement' AND status='queued'`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

func TestUpdatePolicyLateAuditFailurePreservesAllTargets(t *testing.T) {
	s, permissions, _, d := profileAssignmentAccessFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	second, _ := testEnroll(t, s, scope, "Owned second update target")
	drainCommands(t, s, second, nil)
	ids := []string{d.ID, second.ID}
	slices.Sort(ids)
	p := &UpdatePolicy{TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: "2026-10-01T18:00:00"}
	require.NoError(t, s.SetUpdatePolicyWithAccess(t.Context(), scope, ids, p, "operator", permissions))
	_, err := s.db.Exec(`CREATE TABLE owned_update_audit_rejection(resource TEXT); CREATE FUNCTION owned_update_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.policy' AND EXISTS(SELECT 1 FROM owned_update_audit_rejection WHERE resource=NEW.resource_id) THEN RAISE EXCEPTION 'owned update audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_update_audit_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_update_audit_failure()`)
	require.NoError(t, err)
	_, err = s.db.Exec(`INSERT INTO owned_update_audit_rejection VALUES($1)`, ids[1])
	require.NoError(t, err)
	require.Error(t, s.SetUpdatePolicyWithAccess(t.Context(), scope, ids, nil, "operator", permissions))
	for _, id := range ids {
		stored, err := s.UpdatePolicy(t.Context(), scope, id)
		require.NoError(t, err)
		require.Equal(t, p.TargetVersion, stored.TargetVersion)
	}
	var count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE request_type='DeclarativeManagement' AND status='queued'`).Scan(&count))
	require.Equal(t, 2, count)
}
