package apple

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestProfileGroupAssignmentConcurrentReplayAndOriginalHistory(t *testing.T) {
	s, permissions, p, d, group := profileGroupFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	sources := inventory.DeviceSources{Apple: true}
	key := uuid.NewString()
	assign := func() (*ProfileGroupAssignment, error) {
		return s.AssignProfileFromGroup(ctx, "operator", permissions, scope, sources, p.ID, p.Revision, group.ID, group.Revision, key, []string{d.ID}, "installed")
	}
	var results [2]*ProfileGroupAssignment
	var failures [2]error
	var workers sync.WaitGroup
	for i := range 2 {
		workers.Go(func() { results[i], failures[i] = assign() })
	}
	workers.Wait()
	for i := range 2 {
		require.NoError(t, failures[i])
		require.Equal(t, results[0].ID, results[i].ID)
	}
	original := results[0]
	require.Equal(t, group.Name, original.Group.Name)
	require.Len(t, original.Commands, 1)
	require.Equal(t, d.ID, original.Commands[0].DeviceID)
	var count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&count))
	require.Equal(t, 1, count)
	var encrypted []byte
	require.NoError(t, s.db.QueryRow(`SELECT encrypted_intent FROM mdm_apple_profile_group_assignments WHERE id=$1`, original.ID).Scan(&encrypted))
	require.False(t, bytes.Contains(encrypted, []byte(group.Name)))
	require.False(t, bytes.Contains(encrypted, []byte(d.ID)))
	drainCommands(t, s, d, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID, Name: p.Name, Managed: true}})
	verified, err := s.Assignments(ctx, scope, d.ID)
	require.NoError(t, err)
	require.Len(t, verified, 1)
	require.Equal(t, "verified", verified[0].Status)
	definition := group.DeviceGroupDefinition
	definition.Name, definition.Archived = "A later group name", true
	_, err = inventory.SaveDeviceGroup(ctx, s.db, permissions, "operator", access.Scope{TenantID: 1, SiteID: 1}, group.ID, group.Revision, definition)
	require.NoError(t, err)
	require.NoError(t, s.AssignProfileWithAccess(ctx, scope, p.ID, p.Revision, []string{d.ID}, "removed", "operator", permissions))
	_, err = s.SaveProfile(ctx, 1, p.ID, p.Revision, revisionWiFi(t, "Later catalog revision", "owned-new-secret"), "admin")
	require.NoError(t, err)
	replay, err := assign()
	require.NoError(t, err)
	require.Equal(t, original, replay)
	assignments, err := s.Assignments(ctx, scope, d.ID)
	require.NoError(t, err)
	require.Equal(t, "removed", assignments[0].Desired)
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1 AND request_type IN ('InstallProfile','RemoveProfile')`, p.ID).Scan(&count))
	require.Equal(t, 2, count)
	_, err = s.AssignProfileFromGroup(ctx, "operator", permissions, scope, sources, p.ID, p.Revision, group.ID, group.Revision, key, []string{d.ID}, "removed")
	require.ErrorIs(t, err, ErrConflict)
	read, err := s.ProfileGroupAssignmentDetails(ctx, "operator", permissions, scope, p.ID, original.ID)
	require.NoError(t, err)
	require.Equal(t, original, read)
	items, next, err := s.ProfileGroupAssignments(ctx, "operator", permissions, scope, p.ID, "")
	require.NoError(t, err)
	require.Empty(t, next)
	require.Len(t, items, 1)
	_, err = s.ProfileGroupAssignmentDetails(ctx, "viewer", permissions, scope, p.ID, original.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	for _, protected := range []any{read, read.Group, read.Commands[0]} {
		encoded, err := json.Marshal(protected)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(encoded))
	}
	_, err = s.db.Exec(`UPDATE mdm_apple_profile_group_assignments SET desired='removed' WHERE id=$1`, original.ID)
	require.Error(t, err)
}

func TestProfileGroupAssignmentMembershipConflictAndLateAuditRollback(t *testing.T) {
	for _, failure := range []string{"new-member", "late-audit"} {
		t.Run(failure, func(t *testing.T) {
			s, permissions, p, d, group := profileGroupFixture(t)
			ctx := t.Context()
			scope := Scope{TenantID: 1, SiteID: 1}
			if failure == "new-member" {
				second, _ := testEnroll(t, s, scope, "Owned new group member")
				drainCommands(t, s, second, nil)
			} else {
				_, err := s.db.Exec(`CREATE FUNCTION owned_group_assignment_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='apple.profile.group.created' THEN RAISE EXCEPTION 'owned late group assignment failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER owned_group_assignment_audit_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_group_assignment_audit_failure()`)
				require.NoError(t, err)
			}
			r, err := s.AssignProfileFromGroup(ctx, "operator", permissions, scope, inventory.DeviceSources{Apple: true}, p.ID, p.Revision, group.ID, group.Revision, uuid.NewString(), []string{d.ID}, "installed")
			require.Error(t, err)
			require.Nil(t, r)
			if failure == "new-member" {
				require.ErrorIs(t, err, ErrConflict)
			}
			for _, table := range []string{"mdm_apple_profile_assignments", "mdm_apple_profile_group_assignments"} {
				var count int
				require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM `+table).Scan(&count))
				require.Zero(t, count)
			}
			var count int
			require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&count))
			require.Zero(t, count)
		})
	}
}

func TestProfileGroupHistoryPaginationAndCiphertextBinding(t *testing.T) {
	s, permissions, p, d, group := profileGroupFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	var first *ProfileGroupAssignment
	for range 26 {
		r, err := s.AssignProfileFromGroup(ctx, "operator", permissions, scope, inventory.DeviceSources{Apple: true}, p.ID, p.Revision, group.ID, group.Revision, uuid.NewString(), []string{d.ID}, "installed")
		require.NoError(t, err)
		if first == nil {
			first = r
		}
	}
	page, next, err := s.ProfileGroupAssignments(ctx, "operator", permissions, scope, p.ID, "")
	require.NoError(t, err)
	require.Len(t, page, 25)
	require.NotEmpty(t, next)
	last, end, err := s.ProfileGroupAssignments(ctx, "operator", permissions, scope, p.ID, next)
	require.NoError(t, err)
	require.Len(t, last, 1)
	require.Empty(t, end)
	require.Equal(t, first.ID, last[0].ID)
	_, _, err = s.ProfileGroupAssignments(ctx, "admin", permissions, Scope{TenantID: 2, SiteID: 2}, p.ID, next)
	require.ErrorIs(t, err, ErrNotFound)
	badID := uuid.NewString()
	_, err = s.db.Exec(`INSERT INTO mdm_apple_profile_group_assignments(id,tenant_id,site_id,request_key,profile_id,profile_revision,actor,actor_revision,desired,created_at,encrypted_intent) SELECT $1,tenant_id,site_id,$2,profile_id,profile_revision,actor,actor_revision,desired,created_at,encrypted_intent FROM mdm_apple_profile_group_assignments WHERE id=$3`, badID, uuid.NewString(), first.ID)
	require.NoError(t, err)
	read, err := s.ProfileGroupAssignmentDetails(ctx, "operator", permissions, scope, p.ID, badID)
	require.ErrorIs(t, err, ErrProfileGroupIntegrity)
	require.Nil(t, read)
}
