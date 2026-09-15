package inventory

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func CreateLegacyProfile(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, name string) (int64, error) {
	if !(ProfileMetadata{Name: name, Assignment: "dontApplyToAll"}).Valid() {
		return 0, ErrProfileInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileScopeTransaction(ctx, db, permissions, actor, scope)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	id, err := insertUnassignedProfile(ctx, tx, scope, name)
	if err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.profiles.create',$4)", scope.TenantID, scope.SiteID, actor, strconv.FormatInt(id, 10)); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

func insertUnassignedProfile(ctx context.Context, tx *sql.Tx, scope access.Scope, name string) (int64, error) {
	var id int64
	var err error
	if err = tx.QueryRowContext(ctx, "INSERT INTO profiles(name,apply_to_all,type,disabled) VALUES($1,false,'winget',false) RETURNING id", name).Scan(&id); err != nil {
		return 0, err
	}
	if scope.TenantID != 0 {
		if _, err = tx.ExecContext(ctx, "INSERT INTO tenant_profiles(tenant_id,profile_id) VALUES($1,$2)", scope.TenantID, id); err != nil {
			return 0, err
		}
	}
	if scope.SiteID != 0 {
		if _, err = tx.ExecContext(ctx, "INSERT INTO site_profiles(site_id,profile_id) VALUES($1,$2)", scope.SiteID, id); err != nil {
			return 0, err
		}
	}
	return id, nil
}
