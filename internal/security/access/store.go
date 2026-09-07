package access

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"
)

var (
	ErrDenied            = errors.New("permission denied")
	ErrConflict          = errors.New("permissions changed; reload before saving")
	ErrLastAdministrator = errors.New("at least one server administrator must remain")
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct{ db *sql.DB }

func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("access control requires a database")
	}
	return &Store{db: db}, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627902)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS uem_access_migrations(name TEXT PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var applied bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_access_migrations WHERE name=$1)`, name).Scan(&applied); err != nil {
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
			return fmt.Errorf("access migration %s: %w", name, err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_access_migrations(name) VALUES($1)`, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Bootstrap elevates one explicitly selected existing account exactly once.
// Restarts or later environment changes cannot re-grant a revoked privilege.
func (s *Store) Bootstrap(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.New("an initial administrator account is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627902)`); err != nil {
		return err
	}
	var initialized bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_access_migrations WHERE name='bootstrap')`).Scan(&initialized); err != nil {
		return err
	}
	if initialized {
		return tx.Commit()
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE uid=$1)`, userID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errors.New("initial administrator account does not exist")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_access_revisions(user_id,revision) VALUES($1,1)`, userID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_access_grants(user_id,role) VALUES($1,'administrator')`, userID); err != nil {
		return err
	}
	after, _ := json.Marshal([]Grant{{Role: Administrator}})
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_access_audit(actor,subject,action,before_grants,after_grants) VALUES('installation',$1,'bootstrap','[]',$2)`, userID, after); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_access_migrations(name) VALUES('bootstrap')`); err != nil {
		return err
	}
	return tx.Commit()
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func principal(ctx context.Context, q queryer, userID string) (Principal, error) {
	p := Principal{UserID: userID, Grants: []Grant{}}
	// One statement observes a consistent revision/grant snapshot during edits.
	rows, err := q.QueryContext(ctx, `SELECT COALESCE(r.revision,0),g.role,g.tenant_id,g.site_id FROM users u LEFT JOIN uem_access_revisions r ON r.user_id=u.uid LEFT JOIN uem_access_grants g ON g.user_id=u.uid WHERE u.uid=$1 ORDER BY g.tenant_id,g.site_id`, userID)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		found = true
		var role sql.NullString
		var tenant, site sql.NullInt64
		if err = rows.Scan(&p.Revision, &role, &tenant, &site); err != nil {
			return p, err
		}
		if role.Valid {
			p.Grants = append(p.Grants, Grant{Role: Role(role.String), Scope: Scope{TenantID: int(tenant.Int64), SiteID: int(site.Int64)}})
		}
	}
	if err = rows.Err(); err != nil {
		return p, err
	}
	if !found {
		return p, ErrDenied
	}
	return p, nil
}

func (s *Store) Principal(ctx context.Context, userID string) (Principal, error) {
	return principal(ctx, s.db, userID)
}

// ReplaceGrants serializes authorization edits, rechecks the actor inside the
// transaction and rejects stale editors or removal of the final administrator.
func (s *Store) ReplaceGrants(ctx context.Context, actor, subject string, expected int, grants []Grant) error {
	if len(grants) > 256 {
		return errors.New("too many permission assignments")
	}
	seen := map[Scope]bool{}
	for _, g := range grants {
		if err := g.Validate(); err != nil {
			return err
		}
		if seen[g.Scope] {
			return errors.New("duplicate permission scope")
		}
		seen[g.Scope] = true
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627902)`); err != nil {
		return err
	}
	operator, err := principal(ctx, tx, actor)
	if err != nil {
		return err
	}
	if !operator.IsAdministrator() {
		return ErrDenied
	}
	before, err := principal(ctx, tx, subject)
	if err != nil {
		return err
	}
	if before.Revision != expected {
		return ErrConflict
	}
	for _, g := range grants {
		if g.TenantID == 0 {
			continue
		}
		var exists bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1) AND ($2=0 OR EXISTS(SELECT 1 FROM sites WHERE id=$2 AND tenant_sites=$1))`, g.TenantID, g.SiteID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return errors.New("permission organization or site does not exist")
		}
	}
	after := Principal{UserID: subject, Grants: grants}
	if before.IsAdministrator() && !after.IsAdministrator() {
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM uem_access_grants WHERE role='administrator'`).Scan(&count); err != nil {
			return err
		}
		if count <= 1 {
			return ErrLastAdministrator
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM uem_access_grants WHERE user_id=$1`, subject); err != nil {
		return err
	}
	for _, g := range grants {
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_access_grants(user_id,role,tenant_id,site_id) VALUES($1,$2,$3,$4)`, subject, g.Role, g.TenantID, g.SiteID); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_access_revisions(user_id,revision) VALUES($1,1) ON CONFLICT(user_id) DO UPDATE SET revision=uem_access_revisions.revision+1`, subject); err != nil {
		return err
	}
	oldJSON, _ := json.Marshal(before.Grants)
	if grants == nil {
		grants = []Grant{}
	}
	newJSON, _ := json.Marshal(grants)
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_access_audit(actor,subject,action,before_grants,after_grants) VALUES($1,$2,'permissions.replace',$3,$4)`, actor, subject, oldJSON, newJSON); err != nil {
		return err
	}
	return tx.Commit()
}

type AuditEvent struct {
	ID                     int64
	Actor, Subject, Action string
	Before, After          json.RawMessage
	CreatedAt              time.Time
}

func (s *Store) Audit(ctx context.Context, actor string, beforeID int64) ([]AuditEvent, error) {
	p, err := s.Principal(ctx, actor)
	if err != nil {
		return nil, err
	}
	if !p.IsAdministrator() {
		return nil, ErrDenied
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,actor,subject,action,before_grants,after_grants,created_at FROM uem_access_audit WHERE ($1=0 OR id<$1) ORDER BY id DESC LIMIT 100`, beforeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		if err = rows.Scan(&e.ID, &e.Actor, &e.Subject, &e.Action, &e.Before, &e.After, &e.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
