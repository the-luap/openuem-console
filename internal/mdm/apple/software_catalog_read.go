package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

// Catalog pages return only after current read authority and the read audit
// commit together. Immutable approvals do not waive current reader permissions.
func (s *Store) ReadSoftwareCatalog(ctx context.Context, scope Scope, before, query, platform, actor string, permissions *access.Store) ([]SoftwareVersion, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.softwareReadTransaction(ctx, scope, actor, permissions)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	items, next, err := querySoftwareVersions(ctx, tx, scope, before, query, false, "", platform)
	if err != nil {
		return nil, "", err
	}
	if err = softwareReadAudit(ctx, tx, scope, actor, "catalog"); err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return items, next, nil
}

func (s *Store) ReadSoftwareVersion(ctx context.Context, scope Scope, id, actor string, permissions *access.Store) (*SoftwareVersion, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.softwareReadTransaction(ctx, scope, actor, permissions)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	v, err := softwareVersionTx(ctx, tx, scope, id)
	if err != nil {
		return nil, err
	}
	if v.Kind == "windows-msi" || v.Kind == "windows-burn" {
		v.WinGetSource, err = s.readWindowsDerivedSource(ctx, tx, scope, *v)
		if err != nil {
			return nil, err
		}
	}
	if err = softwareReadAudit(ctx, tx, scope, actor, id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return v, nil
}

func (s *Store) softwareReadTransaction(ctx context.Context, scope Scope, actor string, permissions *access.Store) (*sql.Tx, error) {
	if scope.Validate() != nil || actor == "" || permissions == nil {
		return nil, access.ErrDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ReadSoftware, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func softwareReadAudit(ctx context.Context, tx *sql.Tx, scope Scope, actor, resource string) error {
	details, err := json.Marshal(map[string]any{"site_id": scope.SiteID, "result": "success"})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,details) VALUES($1,$2,'software.catalog.read',$3,$4)`, scope.TenantID, actor, resource, details)
	return err
}
