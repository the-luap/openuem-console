package inventory

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

// ChangeDesktopTag changes one membership without replacing other assignments.
// The legacy desktop action remains restricted to server administrators.
func ChangeDesktopTag(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, deviceID string, tagID int64, assigned bool) error {
	if !ValidReportDeviceID(deviceID) || tagID <= 0 {
		return ErrTagInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginGroupTransaction(ctx, db, permissions, actor, scope, access.ManageTags)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageTags, access.Scope{}); err != nil {
		return err
	}
	// Preserve the complete site membership, including edges outside this scope.
	if _, err = tx.ExecContext(ctx, `LOCK TABLE site_agents IN SHARE MODE`); err != nil {
		return err
	}
	var actual access.Scope
	var status string
	err = tx.QueryRowContext(ctx, `SELECT s.tenant_sites,s.id,a.agent_status FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites s ON s.id=sa.site_id
 WHERE a.oid=$1 AND s.tenant_sites=$2 AND ($3::bigint=0 OR s.id=$3) AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1
 FOR UPDATE OF a FOR SHARE OF s`, deviceID, scope.TenantID, scope.SiteID).Scan(&actual.TenantID, &actual.SiteID, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status != "Enabled" && status != "No contact" && status != "Disabled" {
		return ErrNotFound
	}
	var tagTenant sql.NullInt64
	var revision string
	err = tx.QueryRowContext(ctx, `SELECT tenant_tags,uem_revision::text FROM tags WHERE id=$1 FOR SHARE`, tagID).Scan(&tagTenant, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !tagTenant.Valid || tagTenant.Int64 != int64(actual.TenantID) {
		if assigned {
			return ErrNotFound
		}
		// An administrator may repair an existing legacy cross-organization edge.
		// A foreign tag with no such edge is never disclosed or audited as a target.
		var exists bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM agent_tags WHERE agent_id=$1 AND tag_id=$2)`, deviceID, tagID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
	}
	action := "unassign"
	if assigned {
		action = "assign"
		_, err = tx.ExecContext(ctx, `INSERT INTO agent_tags(agent_id,tag_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, deviceID, tagID)
	} else {
		_, err = tx.ExecContext(ctx, `DELETE FROM agent_tags WHERE agent_id=$1 AND tag_id=$2`, deviceID, tagID)
	}
	if err != nil {
		return err
	}
	resource := deviceID + "/" + strconv.FormatInt(tagID, 10) + "/" + revision
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,$4,$5)`, actual.TenantID, actual.SiteID, actor, "inventory.tags."+action, resource); err != nil {
		return err
	}
	return tx.Commit()
}
