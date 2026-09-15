// Package desktop coordinates console enrollment with the shared agent registry.
package desktop

import (
	"context"
	"database/sql"
	"embed"
	"encoding/base64"
	"errors"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

type Store struct {
	Registry *registry.Store
	db       *sql.DB
}

func NewStore(db *sql.DB, masterKey string) (*Store, error) {
	identity, err := registry.NewStore(db, masterKey)
	if err != nil {
		return nil, err
	}
	return &Store{Registry: identity, db: db}, nil
}

//go:embed migrations/*.sql
var migrations embed.FS

func (s *Store) Migrate(ctx context.Context) error {
	if err := s.Registry.Migrate(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627912)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS uem_desktop_migrations(name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var applied bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_desktop_migrations WHERE name=$1)`, name).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(body)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_desktop_migrations(name) VALUES($1)`, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type InvitationRow struct {
	registry.InvitationOptions
	ID        string
	Uses      int
	CreatedAt time.Time
	RevokedAt *time.Time
}

type IdentityRow struct {
	registry.Identity
	EnrolledAt    time.Time
	LastSeenAt    *time.Time
	RevokedAt     *time.Time
	ConsumerReady bool
	ScopeValid    bool
}

// Page uses a bounded keyset cursor. Scope is always an independent SQL predicate,
// so reusing a cursor from another organization cannot expand access.
type Page[T any] struct {
	Rows []T
	Next string
}

type cursor struct {
	at time.Time
	id string
}

func decodeCursor(value string) (cursor, error) {
	if value == "" {
		return cursor{}, nil
	}
	if len(value) > 160 {
		return cursor{}, registry.ErrInvalid
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return cursor{}, registry.ErrInvalid
	}
	parts := strings.Split(string(decoded), "|")
	if len(parts) != 2 || !enrollment.ValidDeviceID(parts[1]) {
		return cursor{}, registry.ErrInvalid
	}
	at, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return cursor{}, registry.ErrInvalid
	}
	return cursor{at: at, id: parts[1]}, nil
}

func encodeCursor(at time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(at.UTC().Format(time.RFC3339Nano) + "|" + id))
}

func (s *Store) readScope(ctx context.Context, scope registry.Scope, actor string) error {
	if scope.TenantID <= 0 || scope.SiteID < 0 || actor == "" || len(actor) > 255 {
		return registry.ErrInvalid
	}
	var valid bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1 AND ($2::bigint=0 OR EXISTS(SELECT 1 FROM sites WHERE id=$2 AND tenant_sites=$1)))`, scope.TenantID, scope.SiteID).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return registry.ErrNotFound
	}
	return nil
}

func (s *Store) auditRead(ctx context.Context, scope registry.Scope, actor, action, id string) error {
	if id == "" {
		id = "00000000-0000-0000-0000-000000000000"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO uem_agent_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,NULLIF($2,0),$3,$4,$5)`, scope.TenantID, scope.SiteID, actor, action, id)
	return err
}

// Authority returns public organization metadata only; encrypted CA keys never
// enter a console view model. Callers enforce certificate administration on writes.
func (s *Store) Authority(ctx context.Context, scope registry.Scope, actor string) (*registry.Authority, error) {
	if err := s.readScope(ctx, scope, actor); err != nil {
		return nil, err
	}
	var authority registry.Authority
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id,organization,public_origin,certificate,expires_at FROM uem_agent_authorities WHERE tenant_id=$1`, scope.TenantID).Scan(&authority.TenantID, &authority.Organization, &authority.PublicOrigin, &authority.Certificate, &authority.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, registry.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = s.auditRead(ctx, scope, actor, "agent.authority.read", ""); err != nil {
		return nil, err
	}
	return &authority, nil
}

func (s *Store) Invitations(ctx context.Context, scope registry.Scope, actor, before string, limit int) (Page[InvitationRow], error) {
	result := Page[InvitationRow]{Rows: []InvitationRow{}}
	if err := s.readScope(ctx, scope, actor); err != nil {
		return result, err
	}
	if limit < 1 || limit > 100 {
		return result, registry.ErrInvalid
	}
	cursor, err := decodeCursor(before)
	if err != nil {
		return result, err
	}
	var at any
	var id any
	if before != "" {
		at, id = cursor.at, cursor.id
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,tenant_id,site_id,platform,architecture,max_uses,uses,expires_at,created_at,revoked_at FROM uem_agent_invitations WHERE tenant_id=$1 AND ($2::bigint=0 OR site_id=$2) AND ($3::timestamptz IS NULL OR (created_at,id)<($3,$4::uuid)) ORDER BY created_at DESC,id DESC LIMIT $5`, scope.TenantID, scope.SiteID, at, id, limit+1)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var item InvitationRow
		if err = rows.Scan(&item.ID, &item.TenantID, &item.SiteID, &item.Platform, &item.Architecture, &item.MaxUses, &item.Uses, &item.ExpiresAt, &item.CreatedAt, &item.RevokedAt); err != nil {
			return result, err
		}
		result.Rows = append(result.Rows, item)
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	rows.Close()
	if len(result.Rows) > limit {
		result.Rows = result.Rows[:limit]
		last := result.Rows[limit-1]
		result.Next = encodeCursor(last.CreatedAt, last.ID)
	}
	if err = s.auditRead(ctx, scope, actor, "agent.invitations.read", ""); err != nil {
		return Page[InvitationRow]{}, err
	}
	return result, nil
}

func (s *Store) Identities(ctx context.Context, scope registry.Scope, actor, before string, limit int) (Page[IdentityRow], error) {
	result := Page[IdentityRow]{Rows: []IdentityRow{}}
	if err := s.readScope(ctx, scope, actor); err != nil {
		return result, err
	}
	if limit < 1 || limit > 100 {
		return result, registry.ErrInvalid
	}
	cursor, err := decodeCursor(before)
	if err != nil {
		return result, err
	}
	var at any
	var id any
	if before != "" {
		at, id = cursor.at, cursor.id
	}
	rows, err := s.db.QueryContext(ctx, `SELECT i.id,i.tenant_id,i.site_id,i.platform,i.architecture,i.display_name,i.certificate_expires_at,i.enrolled_at,i.last_seen_at,i.revoked_at,COALESCE(q.desired_active AND q.completed_revision=q.revision,false),EXISTS(SELECT 1 FROM sites WHERE id=i.site_id AND tenant_sites=i.tenant_id) FROM uem_agent_identities i LEFT JOIN uem_agent_command_consumers q ON q.device_id=i.id WHERE i.tenant_id=$1 AND ($2::bigint=0 OR i.site_id=$2) AND ($3::timestamptz IS NULL OR (i.enrolled_at,i.id)<($3,$4::uuid)) ORDER BY i.enrolled_at DESC,i.id DESC LIMIT $5`, scope.TenantID, scope.SiteID, at, id, limit+1)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var item IdentityRow
		if err = rows.Scan(&item.ID, &item.TenantID, &item.SiteID, &item.Platform, &item.Architecture, &item.DisplayName, &item.CertificateExpiresAt, &item.EnrolledAt, &item.LastSeenAt, &item.RevokedAt, &item.ConsumerReady, &item.ScopeValid); err != nil {
			return result, err
		}
		result.Rows = append(result.Rows, item)
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	rows.Close()
	if len(result.Rows) > limit {
		result.Rows = result.Rows[:limit]
		last := result.Rows[limit-1]
		result.Next = encodeCursor(last.EnrolledAt, last.ID)
	}
	if err = s.auditRead(ctx, scope, actor, "agent.identities.read", ""); err != nil {
		return Page[IdentityRow]{}, err
	}
	return result, nil
}
