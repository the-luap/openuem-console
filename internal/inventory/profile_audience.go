package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

// PromoteProfileAudience supports only the existing site-to-organization and
// organization/site-to-global actions. The destination is derived from the
// verified source; callers cannot supply an unrelated destination organization.
func PromoteProfileAudience(parent context.Context, db *sql.DB, permissions *access.Store, actor string, source access.Scope, profileID int64, global bool) error {
	if source.TenantID <= 0 || source.SiteID < 0 || !global && source.SiteID == 0 {
		return ErrProfileInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileAudienceTransaction(ctx, db, permissions, actor, source, profileID, true)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	destination := access.Scope{TenantID: source.TenantID}
	action := "inventory.profiles.move_organization"
	if global {
		destination = access.Scope{}
		action = "inventory.profiles.move_global"
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM site_profiles WHERE profile_id=$1`, profileID); err != nil {
		return err
	}
	if global {
		if _, err = tx.ExecContext(ctx, `DELETE FROM tenant_profiles WHERE profile_id=$1`, profileID); err != nil {
			return err
		}
	}
	// Both scopes retain a receipt, including the original site after a move.
	// No task, tag, assignment mode or enabled state is changed by this action.
	resource := fmt.Sprintf("%d/from/%d/%d/to/%d/%d", profileID, source.TenantID, source.SiteID, destination.TenantID, destination.SiteID)
	for _, scope := range []access.Scope{source, destination} {
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,$4,$5)`, scope.TenantID, scope.SiteID, actor, action, resource); err != nil {
			return err
		}
	}
	return tx.Commit()
}
