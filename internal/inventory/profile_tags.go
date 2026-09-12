package inventory

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

// ChangeProfileTag retains the exact global, organization or site scope of a
// legacy task profile. It does not grant access to other legacy profile actions.
func ChangeProfileTag(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID, tagID int64, assigned bool) error {
	if profileID <= 0 || tagID <= 0 {
		return ErrTagInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileTransaction(ctx, db, permissions, actor, scope, profileID)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owner sql.NullInt64
	var revision string
	err = tx.QueryRowContext(ctx, `SELECT tenant_tags,uem_revision::text FROM tags WHERE id=$1 FOR SHARE`, tagID).Scan(&owner, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	// A global profile may target tags from any organization. Scoped profiles
	// may target only their own organization; existing foreign edges can be removed.
	within := owner.Valid && owner.Int64 > 0 && (scope.TenantID == 0 || owner.Int64 == int64(scope.TenantID))
	if !within {
		if assigned {
			return ErrNotFound
		}
		var exists bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM profile_tags WHERE profile_id=$1 AND tag_id=$2)`, profileID, tagID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
	}
	action := "unassign"
	if assigned {
		action = "assign"
		if _, err = tx.ExecContext(ctx, `UPDATE profiles SET apply_to_all=false WHERE id=$1`, profileID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO profile_tags(profile_id,tag_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, profileID, tagID)
	} else {
		_, err = tx.ExecContext(ctx, `DELETE FROM profile_tags WHERE profile_id=$1 AND tag_id=$2`, profileID, tagID)
	}
	if err != nil {
		return err
	}
	resource := strconv.FormatInt(profileID, 10) + "/" + strconv.FormatInt(tagID, 10) + "/" + revision
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,$4,$5)`, scope.TenantID, scope.SiteID, actor, "inventory.profile_tags."+action, resource); err != nil {
		return err
	}
	return tx.Commit()
}
