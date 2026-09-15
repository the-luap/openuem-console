package apple

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func requireSameUpdateGroupAssignment(t *testing.T, expected, actual *UpdatePlanGroupAssignment) {
	t.Helper()
	require.NotNil(t, expected)
	require.NotNil(t, actual)
	// PostgreSQL and JSON may represent the same instant with Local and UTC
	// locations. Compare exact timestamps and every receipt field, without
	// treating the location's internal cache as persisted assignment data.
	want, got := *expected, *actual
	want.CreatedAt, got.CreatedAt = want.CreatedAt.UTC(), got.CreatedAt.UTC()
	want.Plan.CreatedAt, got.Plan.CreatedAt = want.Plan.CreatedAt.UTC(), got.Plan.CreatedAt.UTC()
	require.Equal(t, want, got)
}

func TestUpdateGroupReceiptSourceScopeVersionCompatibility(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	s, scope := f.store, f.scope
	original, err := s.AssignUpdatePlanFromGroup(t.Context(), "operator", f.permissions, scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, 1, uuid.NewString(), f.selection)
	require.NoError(t, err)
	require.Equal(t, scope, original.GroupScope)
	var encrypted []byte
	require.NoError(t, s.db.QueryRow(`SELECT encrypted_intent FROM mdm_apple_update_group_assignments WHERE id=$1`, original.ID).Scan(&encrypted))
	plain, err := s.secrets.open(encrypted, updateGroupPurpose(original))
	require.NoError(t, err)
	defer clear(plain)
	var saved updateGroupIntent
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
			changed, err := s.secrets.seal(data, updateGroupPurpose(original))
			require.NoError(t, err)
			columns := strings.Replace(updateGroupColumns, "CASE WHEN octet_length(encrypted_intent)<=32796 THEN encrypted_intent ELSE NULL END", "$2::bytea", 1)
			result, err := s.scanUpdateGroupAssignment(s.db.QueryRow(`SELECT `+columns+` FROM mdm_apple_update_group_assignments WHERE id=$1`, original.ID, changed))
			if state == "legacy" || state == "current" {
				require.NoError(t, err)
				requireSameUpdateGroupAssignment(t, original, result)
			} else {
				require.ErrorIs(t, err, ErrUpdatePlanGroupIntegrity)
				require.Nil(t, result)
			}
		})
	}
}
