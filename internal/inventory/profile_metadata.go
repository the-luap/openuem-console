package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type ProfileMetadata struct{ Name, Assignment string }

func (d ProfileMetadata) Valid() bool {
	if strings.TrimSpace(d.Name) == "" || len(d.Name) > 2048 || !utf8.ValidString(d.Name) || strings.IndexFunc(d.Name, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' }) >= 0 {
		return false
	}
	switch d.Assignment {
	case "applyToAll", "dontApplyToAll", "useTags":
		return true
	}
	return false
}

func SaveProfileMetadata(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID int64, definition ProfileMetadata) error {
	if !definition.Valid() {
		return ErrProfileInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileTransaction(ctx, db, permissions, actor, scope, profileID)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE profiles SET name=$1,apply_to_all=$2 WHERE id=$3`, definition.Name, definition.Assignment == "applyToAll", profileID); err != nil {
		return err
	}
	if definition.Assignment != "useTags" {
		if _, err = tx.ExecContext(ctx, `DELETE FROM profile_tags WHERE profile_id=$1`, profileID); err != nil {
			return err
		}
	}
	resource := fmt.Sprintf("%d/assignment/%s", profileID, definition.Assignment)
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.profiles.update',$4)`, scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return err
	}
	return tx.Commit()
}
