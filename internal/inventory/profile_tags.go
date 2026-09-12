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
	if db == nil || permissions == nil || scope.TenantID < 0 || scope.SiteID < 0 || scope.TenantID == 0 && scope.SiteID != 0 {
		return access.ErrDenied
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	var tx *sql.Tx
	var err error
	if scope.TenantID == 0 {
		tx, err = db.BeginTx(ctx, nil)
	} else {
		tx, err = beginGroupTransaction(ctx, db, permissions, actor, scope, access.ManageProfiles)
	}
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageProfiles, access.Scope{}); err != nil {
		return err
	}
	// Count the complete audience, including otherwise hidden edges. A legacy
	// profile with ambiguous ownership must not be edited through a smaller URL.
	if _, err = tx.ExecContext(ctx, `LOCK TABLE tenant_profiles,site_profiles IN SHARE MODE`); err != nil {
		return err
	}
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT p.id FROM profiles p WHERE p.id=$1
 AND (SELECT count(*) FROM (SELECT 1 FROM tenant_profiles WHERE profile_id=p.id LIMIT 2) audience) = CASE WHEN $2::bigint=0 THEN 0 ELSE 1 END
 AND (SELECT count(*) FROM (SELECT 1 FROM site_profiles WHERE profile_id=p.id LIMIT 2) audience) = CASE WHEN $3::bigint=0 THEN 0 ELSE 1 END
 AND ($2::bigint=0 OR EXISTS(SELECT 1 FROM tenant_profiles WHERE profile_id=p.id AND tenant_id=$2))
 AND ($3::bigint=0 OR EXISTS(SELECT 1 FROM site_profiles WHERE profile_id=p.id AND site_id=$3))
 FOR UPDATE OF p`, profileID, scope.TenantID, scope.SiteID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
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
