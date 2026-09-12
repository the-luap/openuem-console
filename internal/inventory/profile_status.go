package inventory

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrProfileInvalid = errors.New("invalid legacy profile")

// The caller supplies a bounded action context. The returned transaction holds
// current server authority and the complete profile audience until completion.
func beginLegacyProfileTransaction(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID int64) (*sql.Tx, error) {
	if profileID <= 0 {
		return nil, ErrProfileInvalid
	}
	if db == nil || permissions == nil || scope.TenantID < 0 || scope.SiteID < 0 || scope.TenantID == 0 && scope.SiteID != 0 {
		return nil, access.ErrDenied
	}
	var tx *sql.Tx
	var err error
	if scope.TenantID == 0 {
		tx, err = db.BeginTx(ctx, nil)
	} else {
		tx, err = beginGroupTransaction(ctx, db, permissions, actor, scope, access.ManageProfiles)
	}
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*sql.Tx, error) { tx.Rollback(); return nil, err }
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageProfiles, access.Scope{}); err != nil {
		return fail(err)
	}
	// Count all audience edges, including associations hidden by the route.
	if _, err = tx.ExecContext(ctx, `LOCK TABLE tenant_profiles,site_profiles IN SHARE MODE`); err != nil {
		return fail(err)
	}
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT p.id FROM profiles p WHERE p.id=$1
 AND (SELECT count(*) FROM (SELECT 1 FROM tenant_profiles WHERE profile_id=p.id LIMIT 2) audience) = CASE WHEN $2::bigint=0 THEN 0 ELSE 1 END
 AND (SELECT count(*) FROM (SELECT 1 FROM site_profiles WHERE profile_id=p.id LIMIT 2) audience) = CASE WHEN $3::bigint=0 THEN 0 ELSE 1 END
 AND ($2::bigint=0 OR EXISTS(SELECT 1 FROM tenant_profiles WHERE profile_id=p.id AND tenant_id=$2))
 AND ($3::bigint=0 OR EXISTS(SELECT 1 FROM site_profiles WHERE profile_id=p.id AND site_id=$3))
 FOR UPDATE OF p`, profileID, scope.TenantID, scope.SiteID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return fail(ErrNotFound)
	}
	if err != nil {
		return fail(err)
	}
	return tx, nil
}

func SetProfileEnabled(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID int64, enabled bool) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileTransaction(ctx, db, permissions, actor, scope, profileID)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE profiles SET disabled=$1 WHERE id=$2`, !enabled, profileID); err != nil {
		return err
	}
	action := "disable"
	if enabled {
		action = "enable"
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,$4,$5)`, scope.TenantID, scope.SiteID, actor, "inventory.profiles."+action, strconv.FormatInt(profileID, 10)); err != nil {
		return err
	}
	return tx.Commit()
}
