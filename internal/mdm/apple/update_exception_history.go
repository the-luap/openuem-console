package apple

import (
	"context"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

// History retains original scope and IDs. It does not read a moved device's
// current name or settings, and each returned event authenticates its own source.
func (s *Store) UpdateExceptionDetails(ctx context.Context, actor string, permissions *access.Store, scope Scope, deviceID, id string) (*UpdateException, error) {
	if !profileRevisionUUID(deviceID) || !profileRevisionUUID(id) {
		return nil, ErrUpdateException
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = updateExceptionAuthority(ctx, tx, permissions, actor, scope); err != nil {
		return nil, err
	}
	r, err := s.scanUpdateException(tx.QueryRowContext(ctx, `SELECT `+updateExceptionColumns+` FROM mdm_apple_update_exceptions WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND device_id=$4`, id, scope.TenantID, scope.SiteID, deviceID))
	if err != nil {
		return nil, err
	}
	if err = auditUpdateException(ctx, tx, scope, actor, "read", id, r.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) UpdateExceptions(ctx context.Context, actor string, permissions *access.Store, scope Scope, deviceID, before string) ([]UpdateException, string, error) {
	if !profileRevisionUUID(deviceID) || (before != "" && !profileRevisionUUID(before)) {
		return nil, "", ErrUpdateException
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	if err = updateExceptionAuthority(ctx, tx, permissions, actor, scope); err != nil {
		return nil, "", err
	}
	var revision any
	if before != "" {
		anchor, err := s.scanUpdateException(tx.QueryRowContext(ctx, `SELECT `+updateExceptionColumns+` FROM mdm_apple_update_exceptions WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND device_id=$4`, before, scope.TenantID, scope.SiteID, deviceID))
		if err != nil {
			return nil, "", err
		}
		revision = anchor.Revision
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+updateExceptionColumns+` FROM mdm_apple_update_exceptions WHERE tenant_id=$1 AND site_id=$2 AND device_id=$3 AND ($4::integer IS NULL OR revision<$4) ORDER BY revision DESC LIMIT 26`, scope.TenantID, scope.SiteID, deviceID, revision)
	if err != nil {
		return nil, "", err
	}
	items := []UpdateException{}
	for rows.Next() {
		r, err := s.scanUpdateException(rows)
		if err != nil {
			rows.Close()
			return nil, "", err
		}
		items = append(items, *r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > 25 {
		next, items = items[24].ID, items[:25]
	}
	if err = auditUpdateException(ctx, tx, scope, actor, "list", deviceID, 0); err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return items, next, nil
}
