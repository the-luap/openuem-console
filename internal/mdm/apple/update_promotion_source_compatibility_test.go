package apple

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpdatePromotionSourceVersionCompatibilityAndLegacyReplay(t *testing.T) {
	f, _, q := ownedUpdatePromotionFixture(t)
	s, ctx := f.store, t.Context()
	original, err := s.PromoteUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, q)
	require.NoError(t, err)
	stored, err := s.scanUpdatePromotion(s.db.QueryRow(`SELECT `+updatePromotionColumns+` FROM mdm_apple_update_promotions WHERE id=$1`, original.ID))
	require.NoError(t, err)
	var encrypted []byte
	require.NoError(t, s.db.QueryRow(`SELECT encrypted_intent FROM mdm_apple_update_promotions WHERE id=$1`, original.ID).Scan(&encrypted))
	plain, err := s.secrets.open(encrypted, updatePromotionPurpose(stored))
	require.NoError(t, err)
	defer clear(plain)
	var saved updatePromotionWire
	require.NoError(t, json.Unmarshal(plain, &saved))
	require.Equal(t, 2, saved.Version)
	require.Equal(t, f.scope, *saved.GroupScope)
	var legacy []byte
	for _, condition := range []string{"legacy", "current", "missing-source", "foreign-tenant", "foreign-site", "negative-site", "legacy-with-source", "unknown-version"} {
		t.Run(condition, func(t *testing.T) {
			wire := saved
			source := f.scope
			wire.GroupScope = &source
			switch condition {
			case "legacy":
				wire.Version, wire.GroupScope = 1, nil
			case "missing-source":
				wire.GroupScope = nil
			case "foreign-tenant":
				source.TenantID = 2
			case "foreign-site":
				source.SiteID = 3
			case "negative-site":
				source.SiteID = -1
			case "legacy-with-source":
				wire.Version = 1
			case "unknown-version":
				wire.Version = 3
			}
			data, err := json.Marshal(wire)
			require.NoError(t, err)
			defer clear(data)
			changed, err := s.secrets.seal(data, updatePromotionPurpose(stored))
			require.NoError(t, err)
			columns := strings.Replace(updatePromotionColumns, "CASE WHEN octet_length(encrypted_intent)<=131100 THEN encrypted_intent ELSE NULL END", "$2::bytea", 1)
			result, err := s.scanUpdatePromotion(s.db.QueryRow(`SELECT `+columns+` FROM mdm_apple_update_promotions WHERE id=$1`, original.ID, changed))
			if condition == "legacy" || condition == "current" {
				require.NoError(t, err)
				require.Equal(t, stored, result)
			} else {
				require.ErrorIs(t, err, ErrUpdatePromotionIntegrity)
				require.Nil(t, result)
			}
			if condition == "legacy" {
				legacy = changed
			}
		})
	}
	// Simulate a correctly authenticated parent written by the old console,
	// then exercise normal historical source validation and exact replay.
	_, err = s.db.Exec(`ALTER TABLE mdm_apple_update_promotions DISABLE TRIGGER mdm_apple_keep_update_promotion`)
	require.NoError(t, err)
	_, changeErr := s.db.Exec(`UPDATE mdm_apple_update_promotions SET encrypted_intent=$1 WHERE id=$2`, legacy, original.ID)
	_, restoreErr := s.db.Exec(`ALTER TABLE mdm_apple_update_promotions ENABLE TRIGGER mdm_apple_keep_update_promotion`)
	require.NoError(t, restoreErr)
	require.NoError(t, changeErr)
	require.NoError(t, s.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, nil, "operator", f.permissions))
	p0, a0, n0 := f.counts(t)
	replay, err := s.PromoteUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, q)
	require.NoError(t, err)
	require.Equal(t, original.ID, replay.ID)
	require.Equal(t, f.scope, replay.GroupScope)
	p, a, n := f.counts(t)
	require.Equal(t, []int{p0, a0, n0}, []int{p, a, n})
	detail, err := s.UpdatePromotionDetails(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, original.ID)
	require.NoError(t, err)
	require.Equal(t, replay.GroupScope, detail.Assignment.GroupScope)
}
