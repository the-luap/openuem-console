package windows

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"io/fs"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var (
	ErrStore      = errors.New("native Windows enrollment requires PostgreSQL")
	ErrInvitation = errors.New("invalid native Windows enrollment invitation")
	ErrNotFound   = errors.New("native Windows enrollment resource not found")
)

type Store struct {
	db          *sql.DB
	permissions *access.Store
}

func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, ErrStore
	}
	permissions, err := access.NewStore(db)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, permissions: permissions}, nil
}

//go:embed migrations/*.sql
var migrations embed.FS

// Migrate only adds native Windows tables. The upstream organization/site/user
// schema and console access migrations must already exist. Native Windows MDM
// has no production startup registration yet.
func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627940)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS mdm_windows_migrations(name TEXT PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var applied bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_windows_migrations WHERE name=$1)`, name).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_migrations(name) VALUES($1)`, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Lock the actual site/organization relationship, not just foreign keys or
// caller-supplied IDs. Reparenting/deletion cannot race a granted transaction.
func lockEnrollmentScope(ctx context.Context, tx *sql.Tx, scope access.Scope) error {
	if scope.TenantID <= 0 || scope.SiteID <= 0 {
		return ErrInvitation
	}
	var id int
	err := tx.QueryRowContext(ctx, `SELECT s.id FROM sites s JOIN tenants t ON t.id=s.tenant_sites WHERE t.id=$1 AND s.id=$2 FOR SHARE OF s,t`, scope.TenantID, scope.SiteID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (s *Store) authorizeInvitationConsole(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope) error {
	if len(actor) == 0 || len(actor) > 255 || !utf8.ValidString(actor) || strings.IndexFunc(actor, unicode.IsControl) >= 0 || scope.TenantID <= 0 || scope.SiteID <= 0 {
		return ErrInvitation
	}
	if err := s.permissions.AuthorizeTransaction(ctx, tx, actor, access.EnrollDevices, scope); err != nil {
		return err
	}
	return lockEnrollmentScope(ctx, tx, scope)
}

func auditInvitation(ctx context.Context, tx *sql.Tx, invitation EnrollmentInvitation, actor, action string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,$4,$5)`, invitation.TenantID, invitation.SiteID, actor, action, invitation.ID)
	return err
}
