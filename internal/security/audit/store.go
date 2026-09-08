// Package audit provides scoped access to existing management audit records.
package audit

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var (
	ErrInvalid  = errors.New("invalid audit filter or cursor")
	ErrTooLarge = errors.New("the export exceeds 10000 events; narrow the filters")
	ErrConflict = errors.New("audit retention changed; reload before saving")
	ErrBusy     = errors.New("audit exports are busy; retry shortly")
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	db          *sql.DB
	permissions *access.Store
	exports     chan struct{}
}

func NewStore(db *sql.DB, permissions *access.Store) (*Store, error) {
	if db == nil || permissions == nil {
		return nil, errors.New("audit requires a database and access control")
	}
	return &Store{db: db, permissions: permissions, exports: make(chan struct{}, 2)}, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684628901)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS uem_audit_migrations(name TEXT PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var applied bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_audit_migrations WHERE name=$1)`, name).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		data, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(data)); err != nil {
			return fmt.Errorf("audit migration %s: %w", name, err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_audit_migrations(name) VALUES($1)`, name); err != nil {
			return err
		}
	}
	available, err := availableSources(ctx, tx)
	if err != nil {
		return err
	}
	for i, source := range sourceQueries {
		if !available[i] {
			continue
		}
		// Recheck optional sources at startup even if the audit migration already
		// ran before that platform was configured. These are fixed source names.
		if source.name != "release" && source.name != "activity" {
			if _, err = tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS `+source.table+`_timeline ON `+source.table+`(created_at DESC,id DESC)`); err != nil {
				return err
			}
		}
		if source.name == "apple" || source.name == "agent" {
			if _, err = tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS `+source.table+`_tenant_timeline ON `+source.table+`(tenant_id,created_at DESC,id DESC)`); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) authorize(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope) error {
	return s.authorizeScope(ctx, tx, actor, scope, access.ReadAudit)
}

func (s *Store) authorizeScope(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope, capability access.Capability) error {
	if err := s.permissions.AuthorizeTransaction(ctx, tx, actor, capability, scope); err != nil {
		return err
	}
	if scope.TenantID == 0 {
		return nil
	}
	var exists bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1 AND ($2::bigint=0 OR EXISTS(SELECT 1 FROM sites WHERE id=$2 AND tenant_sites=$1)))`, scope.TenantID, scope.SiteID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return access.ErrDenied
	}
	return nil
}

type Event struct {
	ID        int64     `json:"id"`
	Source    string    `json:"source"`
	TenantID  int       `json:"tenant_id"`
	SiteID    int       `json:"site_id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Result    string    `json:"result"`
	CreatedAt time.Time `json:"created_at"`
}

type Page struct {
	Events  []Event
	Next    string
	Sources []string
}
