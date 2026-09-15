package apple

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestProfileOrganizationGroupLateAuditFailureRollsBackCompleteAdmission(t *testing.T) {
	s, permissions, p, d, _ := profileGroupFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	group, err := inventory.SaveDeviceGroup(ctx, s.db, permissions, "organization", access.Scope{TenantID: 1}, "", 0, inventory.DeviceGroupDefinition{Name: "Owned audited organization group"})
	require.NoError(t, err)
	_, err = s.db.Exec(`CREATE FUNCTION reject_organization_assignment_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.profile.group.created' THEN RAISE EXCEPTION 'owned organization assignment audit failure'; END IF; RETURN NEW; END; $$; CREATE TRIGGER reject_organization_assignment_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_organization_assignment_audit()`)
	require.NoError(t, err)
	result, err := s.AssignProfileFromOrganizationGroup(ctx, "organization", permissions, scope, inventory.DeviceSources{Apple: true}, p.ID, p.Revision, group.ID, 1, uuid.NewString(), []string{d.ID}, "installed")
	require.Error(t, err)
	require.Nil(t, result)
	var commands, receipts int
	require.NoError(t, s.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1),(SELECT count(*) FROM mdm_apple_profile_group_assignments WHERE profile_id=$1)`, p.ID).Scan(&commands, &receipts))
	require.Zero(t, commands)
	require.Zero(t, receipts)
	assignments, err := s.Assignments(ctx, scope, d.ID)
	require.NoError(t, err)
	require.Empty(t, assignments)
}

func TestProfileOrganizationGroupKeepsSourceTargetAndAuthorityLockedThroughFinalAudit(t *testing.T) {
	s, permissions, p, d, _ := profileGroupFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	definition := inventory.DeviceGroupDefinition{Name: "Owned locked organization group"}
	group, err := inventory.SaveDeviceGroup(ctx, s.db, permissions, "organization", access.Scope{TenantID: 1}, "", 0, definition)
	require.NoError(t, err)
	const gate = 673810055
	conn, err := s.db.Conn(ctx)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, gate)
	require.NoError(t, err)
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, gate)
	_, err = s.db.Exec(`CREATE SEQUENCE organization_assignment_audit_entered; CREATE FUNCTION gate_organization_assignment_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.profile.group.created' THEN PERFORM nextval('organization_assignment_audit_entered'); PERFORM pg_advisory_xact_lock(673810055); END IF; RETURN NEW; END; $$; CREATE TRIGGER gate_organization_assignment_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION gate_organization_assignment_audit()`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := s.AssignProfileFromOrganizationGroup(ctx, "organization", permissions, scope, inventory.DeviceSources{Apple: true}, p.ID, p.Revision, group.ID, 1, uuid.NewString(), []string{d.ID}, "installed")
		done <- err
	}()
	require.Eventually(t, func() bool {
		var entered bool
		err := s.db.QueryRow(`SELECT is_called FROM organization_assignment_audit_entered`).Scan(&entered)
		return err == nil && entered
	}, 3*time.Second, 10*time.Millisecond)
	for _, change := range []string{"group", "site", "device", "permission"} {
		t.Run(change, func(t *testing.T) {
			bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
			defer cancel()
			var err error
			switch change {
			case "group":
				definition.Archived = true
				_, err = inventory.SaveDeviceGroup(bounded, s.db, permissions, "organization", access.Scope{TenantID: 1}, group.ID, 1, definition)
			case "site":
				_, err = s.db.ExecContext(bounded, `UPDATE sites SET tenant_sites=2 WHERE id=1`)
			case "device":
				_, err = s.db.ExecContext(bounded, `UPDATE mdm_apple_devices SET site_id=2 WHERE id=$1`, d.ID)
			case "permission":
				err = permissions.ReplaceGrants(bounded, "admin", "organization", 1, nil)
			}
			require.Error(t, err)
		})
	}
	_, err = conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gate)
	require.NoError(t, err)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("organization assignment did not finish after audit release")
	}
	var assigned bool
	err = s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM mdm_apple_profile_group_assignments WHERE profile_id=$1)`, p.ID).Scan(&assigned)
	require.NoError(t, err)
	require.True(t, assigned)
	require.NoError(t, permissions.ReplaceGrants(ctx, "admin", "organization", 1, nil))
	// The source grant must still be required after the original admission.
	result, err := s.PreviewProfileOrganizationGroup(ctx, "organization", permissions, scope, inventory.DeviceSources{Apple: true}, p.ID, p.Revision, group.ID, 1, "installed")
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, result)
}
