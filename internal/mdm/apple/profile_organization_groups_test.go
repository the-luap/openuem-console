package apple

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestProfileOrganizationGroupPreviewsAndAdmitsOnlyReviewedSiteIntersection(t *testing.T) {
	s, permissions, p, d, _ := profileGroupFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	sources := inventory.DeviceSources{Apple: true}
	_, err := s.db.Exec(`INSERT INTO sites(id,tenant_sites) VALUES(3,1)`)
	require.NoError(t, err)
	outside, _ := testEnroll(t, s, Scope{TenantID: 1, SiteID: 3}, "Other site private native device")
	drainCommands(t, s, outside, nil)
	definition := inventory.DeviceGroupDefinition{Name: "Owned <organization source>"}
	group, err := inventory.SaveDeviceGroup(ctx, s.db, permissions, "organization", access.Scope{TenantID: 1}, "", 0, definition)
	require.NoError(t, err)
	preview, err := s.PreviewProfileOrganizationGroup(ctx, "organization", permissions, scope, sources, p.ID, p.Revision, group.ID, 1, "installed")
	require.NoError(t, err)
	require.Zero(t, preview.Group.Scope.SiteID)
	require.Len(t, preview.Targets, 1)
	require.Equal(t, d.ID, preview.Targets[0].DeviceID)
	require.Len(t, preview.Excluded, 1)
	require.Equal(t, "owned-desktop", preview.Excluded[0].Entry.ID)
	var commands int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&commands))
	require.Zero(t, commands)
	for _, actor := range []string{"operator", "viewer"} {
		result, err := s.PreviewProfileOrganizationGroup(ctx, actor, permissions, scope, sources, p.ID, p.Revision, group.ID, 1, "installed")
		require.ErrorIs(t, err, access.ErrDenied)
		require.Nil(t, result)
	}
	_, err = s.PreviewProfileGroup(ctx, "organization", permissions, scope, sources, p.ID, p.Revision, group.ID, 1, "installed")
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = s.AssignProfileFromOrganizationGroup(ctx, "organization", permissions, scope, sources, p.ID, p.Revision, group.ID, 1, uuid.NewString(), []string{d.ID, outside.ID}, "installed")
	require.ErrorIs(t, err, ErrConflict)
	key := uuid.NewString()
	var receipts [2]*ProfileGroupAssignment
	var failures [2]error
	var workers sync.WaitGroup
	for i := range 2 {
		workers.Go(func() {
			receipts[i], failures[i] = s.AssignProfileFromOrganizationGroup(ctx, "organization", permissions, scope, sources, p.ID, p.Revision, group.ID, 1, key, []string{d.ID}, "installed")
		})
	}
	workers.Wait()
	for i := range receipts {
		require.NoError(t, failures[i])
		require.Equal(t, receipts[0], receipts[i])
	}
	original := receipts[0]
	require.Equal(t, Scope{TenantID: 1}, original.GroupScope)
	require.Equal(t, scope, original.Scope)
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1 AND device_id=$2`, p.ID, outside.ID).Scan(&commands))
	require.Zero(t, commands)
	drainCommands(t, s, d, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID, Name: p.Name, Managed: true}})
	assignments, err := s.Assignments(ctx, scope, d.ID)
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	require.Equal(t, "verified", assignments[0].Status)
	definition.Name = "Later organization group"
	definition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, s.db, permissions, "organization", access.Scope{TenantID: 1}, group.ID, 1, definition)
	require.NoError(t, err)
	require.NoError(t, s.AssignProfileWithAccess(ctx, scope, p.ID, p.Revision, []string{d.ID}, "removed", "organization", permissions))
	replay, err := s.AssignProfileFromOrganizationGroup(ctx, "organization", permissions, scope, sources, p.ID, p.Revision, group.ID, 1, key, []string{d.ID}, "installed")
	require.NoError(t, err)
	require.Equal(t, original, replay)
	assignments, err = s.Assignments(ctx, scope, d.ID)
	require.NoError(t, err)
	require.Equal(t, "removed", assignments[0].Desired)
	_, err = s.AssignProfileFromGroup(ctx, "organization", permissions, scope, sources, p.ID, p.Revision, group.ID, 1, key, []string{d.ID}, "installed")
	require.ErrorIs(t, err, ErrConflict)
	detail, err := s.ProfileGroupAssignmentDetails(ctx, "operator", permissions, scope, p.ID, original.ID)
	require.NoError(t, err)
	require.Equal(t, original, detail)
	items, _, err := s.ProfileGroupAssignments(ctx, "operator", permissions, scope, p.ID, "")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, original.GroupScope, items[0].GroupScope)
	require.NoError(t, permissions.ReplaceGrants(ctx, "admin", "organization", 1, []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}))
	_, err = s.AssignProfileFromOrganizationGroup(ctx, "organization", permissions, scope, sources, p.ID, p.Revision, group.ID, 1, key, []string{d.ID}, "installed")
	require.ErrorIs(t, err, access.ErrDenied)
}

func TestProfileGroupReceiptSourceScopeVersionCompatibility(t *testing.T) {
	s, permissions, p, d, group := profileGroupFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	original, err := s.AssignProfileFromGroup(ctx, "operator", permissions, scope, inventory.DeviceSources{Apple: true}, p.ID, p.Revision, group.ID, 1, uuid.NewString(), []string{d.ID}, "installed")
	require.NoError(t, err)
	require.Equal(t, scope, original.GroupScope)
	var encrypted []byte
	require.NoError(t, s.db.QueryRow(`SELECT encrypted_intent FROM mdm_apple_profile_group_assignments WHERE id=$1`, original.ID).Scan(&encrypted))
	plain, err := s.secrets.open(encrypted, profileGroupPurpose(original))
	require.NoError(t, err)
	defer clear(plain)
	var saved profileGroupIntent
	require.NoError(t, json.Unmarshal(plain, &saved))
	require.Equal(t, 2, saved.Version)
	require.Equal(t, scope, *saved.GroupScope)
	for _, state := range []string{"legacy", "current", "missing-source", "foreign-tenant", "foreign-site", "negative-site", "legacy-with-source", "unknown-version"} {
		t.Run(state, func(t *testing.T) {
			intent := saved
			source := scope
			intent.GroupScope = &source
			switch state {
			case "legacy":
				intent.Version = 1
				intent.GroupScope = nil
			case "missing-source":
				intent.GroupScope = nil
			case "foreign-tenant":
				source.TenantID = 2
			case "foreign-site":
				source.SiteID = 3
			case "negative-site":
				source.SiteID = -1
			case "legacy-with-source":
				intent.Version = 1
			case "unknown-version":
				intent.Version = 3
			}
			data, err := json.Marshal(intent)
			require.NoError(t, err)
			defer clear(data)
			changed, err := s.secrets.seal(data, profileGroupPurpose(original))
			require.NoError(t, err)
			columns := strings.Replace(profileGroupColumns, "CASE WHEN octet_length(encrypted_intent)<=16412 THEN encrypted_intent ELSE NULL END", "$2::bytea", 1)
			result, err := s.readProfileGroupAssignment(s.db.QueryRow(`SELECT `+columns+` FROM mdm_apple_profile_group_assignments WHERE id=$1`, original.ID, changed))
			if state == "legacy" || state == "current" {
				require.NoError(t, err)
				require.Equal(t, original, result)
			} else {
				require.ErrorIs(t, err, ErrProfileGroupIntegrity)
				require.Nil(t, result)
			}
		})
	}
}
