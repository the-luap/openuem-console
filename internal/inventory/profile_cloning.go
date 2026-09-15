package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrProfileCloneProviderScope = errors.New("profile registration tasks require their configured organization")

func ReviewProfileClone(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID int64) (*ent.Profile, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileTransaction(ctx, db, permissions, actor, scope, profileID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	p := &ent.Profile{ID: int(profileID)}
	var oversized bool
	if err = tx.QueryRowContext(ctx, "SELECT left(name,2048),octet_length(name)>2048 FROM profiles WHERE id=$1", profileID).Scan(&p.Name, &oversized); err != nil {
		return nil, err
	}
	// Older names may exceed the current form bound. Require an explicit new name.
	if oversized || !(ProfileMetadata{Name: p.Name, Assignment: "dontApplyToAll"}).Valid() {
		p.Name = ""
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}

// Source server authority is already held by the caller. Destination parent
// rows must remain current until its associations and audit receipt commit.
func lockProfileCloneDestination(ctx context.Context, tx *sql.Tx, scope access.Scope) error {
	if scope.TenantID < 0 || scope.SiteID < 0 || scope.TenantID == 0 && scope.SiteID != 0 {
		return ErrProfileInvalid
	}
	if scope.TenantID == 0 {
		return nil
	}
	var id int
	var err error
	if scope.SiteID == 0 {
		err = tx.QueryRowContext(ctx, "SELECT id FROM tenants WHERE id=$1 FOR SHARE", scope.TenantID).Scan(&id)
	} else {
		err = tx.QueryRowContext(ctx, "SELECT s.id FROM sites s JOIN tenants t ON t.id=s.tenant_sites WHERE t.id=$1 AND s.id=$2 FOR SHARE OF s,t", scope.TenantID, scope.SiteID).Scan(&id)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func CloneLegacyProfile(parent context.Context, db *sql.DB, permissions *access.Store, actor string, source, destination access.Scope, profileID int64, name string) (int64, error) {
	if !(ProfileMetadata{Name: name, Assignment: "dontApplyToAll"}).Valid() {
		return 0, ErrProfileInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileAudienceTransaction(ctx, db, permissions, actor, source, profileID, true)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err = lockProfileCloneDestination(ctx, tx, destination); err != nil {
		return 0, err
	}
	// The source profile FOR UPDATE lock prevents new/reassigned task foreign
	// keys. Lock existing tasks before reading their configuration; drain rows
	// without retaining or logging credentials, scripts or other task values.
	rows, err := tx.QueryContext(ctx, "SELECT id FROM tasks WHERE profile_tasks=$1 ORDER BY id FOR SHARE", profileID)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil {
		return 0, err
	}
	if closeErr != nil {
		return 0, closeErr
	}
	var incompatible bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM tasks WHERE profile_tasks=$1 AND type='netbird_register' AND (tenant IS NULL OR tenant<=0 OR tenant!=$2))", profileID, destination.TenantID).Scan(&incompatible); err != nil {
		return 0, err
	}
	if incompatible {
		return 0, ErrProfileCloneProviderScope
	}
	id, err := insertUnassignedProfile(ctx, tx, destination, name)
	if err != nil {
		return 0, err
	}
	// The pinned Ent schema enumerates configuration fields. Copy nullable values
	// directly; fresh identity, version, execution time and deterministic order are
	// deliberate exceptions. Edges to tags and historical results are not copied.
	fields := legacyTaskCopyFields(false)
	result, err := tx.ExecContext(ctx, `INSERT INTO tasks (`+fields+`,version,"order",profile_tasks) SELECT `+fields+`,1,row_number() OVER (ORDER BY "order",id),$2 FROM tasks WHERE profile_tasks=$1`, profileID, id)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	resource := fmt.Sprintf("%d/from/%d/%d/%d/to/%d/%d/tasks/%d", id, profileID, source.TenantID, source.SiteID, destination.TenantID, destination.SiteID, count)
	scopes := []access.Scope{source}
	if source != destination {
		scopes = append(scopes, destination)
	}
	for _, scope := range scopes {
		if _, err = tx.ExecContext(ctx, "INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.profiles.clone',$4)", scope.TenantID, scope.SiteID, actor, resource); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

func ProfileCloneSites(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope) ([]*ent.Site, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileScopeTransaction(ctx, db, permissions, actor, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	sites := []*ent.Site{}
	if scope.TenantID != 0 {
		rows, err := tx.QueryContext(ctx, "SELECT id,left(description,512) FROM sites WHERE tenant_sites=$1 ORDER BY description,id", scope.TenantID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			s := &ent.Site{}
			if err = rows.Scan(&s.ID, &s.Description); err != nil {
				return nil, err
			}
			sites = append(sites, s)
		}
		if err = rows.Err(); err != nil {
			return nil, err
		}
		if err = rows.Close(); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return sites, nil
}
