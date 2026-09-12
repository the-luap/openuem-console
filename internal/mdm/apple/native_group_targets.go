package apple

import (
	"context"
	"database/sql"
	"errors"
	"slices"

	"github.com/open-uem/openuem-console/internal/inventory"
)

// nativeAppleGroupCandidates resolves canonical Mac records to current native
// channels and orders native enrollment IDs for consistent target locking.
// Callers retain the current scope and group snapshot locks in this transaction.
func nativeAppleGroupCandidates(ctx context.Context, tx *sql.Tx, scope Scope, entries []inventory.DeviceEntry) ([]ProfileGroupTarget, []ProfileGroupTarget, error) {
	var err error
	excluded := []ProfileGroupTarget{}
	candidates := []ProfileGroupTarget{}
	seen := map[string]bool{}
	for _, entry := range entries {
		target := ProfileGroupTarget{Entry: entry}
		switch entry.Kind {
		case "apple":
			target.DeviceID = entry.ID
		case "mac":
			err = tx.QueryRowContext(ctx, `SELECT mc.device_id FROM uem_mac_devices m JOIN uem_mac_mdm_channels mc ON mc.entity_id=m.id AND mc.retired_at IS NULL WHERE m.id=$1 AND m.tenant_id=$2 AND m.site_id=$3 FOR SHARE OF m,mc`, entry.ID, scope.TenantID, scope.SiteID).Scan(&target.DeviceID)
			if errors.Is(err, sql.ErrNoRows) {
				target.Reason = "apple_channel_unavailable"
			} else if err != nil {
				return nil, nil, err
			}
		default:
			target.Reason = "not_apple_mdm"
		}
		if target.Reason != "" {
			excluded = append(excluded, target)
			continue
		}
		if seen[target.DeviceID] {
			return nil, nil, ErrProfileGroup
		}
		seen[target.DeviceID] = true
		candidates = append(candidates, target)
	}
	slices.SortFunc(candidates, func(a, b ProfileGroupTarget) int {
		if a.DeviceID < b.DeviceID {
			return -1
		}
		if a.DeviceID > b.DeviceID {
			return 1
		}
		return 0
	})
	return candidates, excluded, nil
}
