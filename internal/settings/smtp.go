// Package settings owns authorized, bounded console configuration operations.
package settings

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var (
	ErrInvalid  = errors.New("invalid SMTP settings")
	ErrNotFound = errors.New("SMTP settings are unavailable in this scope")
	ErrConflict = errors.New("SMTP settings changed; reload before saving")
	ErrSecret   = errors.New("SMTP secret storage is unavailable")
)

type SMTPConfig struct {
	Server     string
	Port       int
	User       string
	Auth       string
	From       string
	Encryption string
}

type SMTPReview struct {
	ID          int64
	Revision    string
	Config      SMTPConfig
	PasswordSet bool
	LastTest    *SMTPTestResult
}

type SMTPStore struct {
	db          *sql.DB
	permissions *access.Store
	key         string
}

func NewSMTPStore(db *sql.DB, permissions *access.Store, masterKey string) (*SMTPStore, error) {
	if db == nil || permissions == nil {
		return nil, ErrInvalid
	}
	return &SMTPStore{db: db, permissions: permissions, key: masterKey}, nil
}

//go:embed migrations/001_smtp.sql
var smtpSchema embed.FS

func (s *SMTPStore) Migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684630101); CREATE TABLE IF NOT EXISTS uem_settings_migrations(name TEXT PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())`); err != nil {
		return err
	}
	var installed bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_settings_migrations WHERE name='001_smtp')`).Scan(&installed); err != nil {
		return err
	}
	if !installed {
		body, err := smtpSchema.ReadFile("migrations/001_smtp.sql")
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(body)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_settings_migrations(name) VALUES('001_smtp')`); err != nil {
			return err
		}
	}
	var guard bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='settings'::regclass AND tgname='uem_smtp_revision' AND tgtype=19 AND tgenabled IN ('O','A') AND tgfoid='uem_smtp_revision()'::regprocedure)
 AND EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid='settings'::regclass AND attname='uem_smtp_revision' AND atttypid='uuid'::regtype AND attnotnull AND NOT attisdropped)
 AND EXISTS(SELECT 1 FROM pg_catalog.pg_index WHERE indexrelid=to_regclass('uem_settings_single_global') AND indrelid='settings'::regclass AND indisunique AND indisvalid AND indisready AND pg_get_expr(indpred,indrelid)='(tenant_settings IS NULL)' AND pg_get_expr(indexprs,indrelid)='true')
 AND to_regclass('uem_smtp_test_attempts') IS NOT NULL`).Scan(&guard); err != nil {
		return err
	}
	if !guard {
		return errors.New("SMTP schema protection is unavailable")
	}
	return tx.Commit()
}

func textBound(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func (c SMTPConfig) Valid() bool {
	if !textBound(c.Server, 253) || c.Server == "" || c.Port < 1 || c.Port > 65535 || !textBound(c.User, 1024) || !textBound(c.From, 320) {
		return false
	}
	if net.ParseIP(c.Server) == nil {
		for _, label := range strings.Split(c.Server, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
					return false
				}
			}
		}
	}
	address, err := mail.ParseAddress(c.From)
	if err != nil || address.Address != c.From || address.Name != "" {
		return false
	}
	switch c.Auth {
	case "NOAUTH", "LOGIN", "PLAIN", "XOAUTH2", "SCRAM-SHA-256":
	default:
		return false
	}
	switch c.Encryption {
	case "none", "smtps", "starttls":
	default:
		return false
	}
	return true
}

func (s *SMTPStore) begin(ctx context.Context, actor string, scope access.Scope) (*sql.Tx, error) {
	if scope.TenantID < 0 || scope.SiteID != 0 {
		return nil, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*sql.Tx, error) { tx.Rollback(); return nil, err }
	if err = s.permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageSettings, access.Scope{}); err != nil {
		return fail(err)
	}
	if scope.TenantID > 0 {
		var id int
		if err = tx.QueryRowContext(ctx, "SELECT id FROM tenants WHERE id=$1 FOR SHARE", scope.TenantID).Scan(&id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fail(ErrNotFound)
			}
			return fail(err)
		}
	}
	return tx, nil
}

// Secret values are evaluated only inside SQL. The returned review has no
// password field, and saving keep never transfers the column to the application.
func readSMTP(ctx context.Context, tx *sql.Tx, scope access.Scope, write bool) (*SMTPReview, error) {
	lock := " FOR SHARE"
	if write {
		lock = " FOR UPDATE"
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,uem_smtp_revision::text,
 CASE WHEN octet_length(smtp_server)<=253 THEN smtp_server ELSE '' END,coalesce(smtp_port,0),
 CASE WHEN octet_length(smtp_user)<=1024 THEN smtp_user ELSE '' END,
 CASE WHEN octet_length(smtp_auth)<=32 THEN smtp_auth ELSE '' END,
 CASE WHEN octet_length(message_from)<=320 THEN message_from ELSE '' END,
 CASE WHEN octet_length(smtp_encryption_type)<=32 THEN smtp_encryption_type ELSE '' END,
 coalesce(smtp_password<>'',false),
 coalesce(octet_length(smtp_server),0)<=253 AND coalesce(octet_length(smtp_user),0)<=1024 AND coalesce(octet_length(message_from),0)<=320 AND coalesce(octet_length(smtp_auth),0)<=32 AND coalesce(octet_length(smtp_encryption_type),0)<=32
 FROM settings WHERE coalesce(tenant_settings,0)=$1 ORDER BY id LIMIT 2`+lock, scope.TenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result *SMTPReview
	for rows.Next() {
		if result != nil {
			return nil, ErrNotFound
		}
		result = &SMTPReview{}
		var bounded bool
		if err = rows.Scan(&result.ID, &result.Revision, &result.Config.Server, &result.Config.Port, &result.Config.User, &result.Config.Auth, &result.Config.From, &result.Config.Encryption, &result.PasswordSet, &bounded); err != nil {
			return nil, err
		}
		if !bounded {
			return nil, ErrConflict
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, ErrNotFound
	}
	return result, nil
}

func smtpAudit(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope, action, resource, result string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO uem_settings_audit(tenant_id,site_id,actor,action,resource_id,result) VALUES($1,0,$2,$3,$4,$5)`, scope.TenantID, actor, action, resource, result)
	return err
}

func (s *SMTPStore) Read(parent context.Context, actor string, scope access.Scope) (*SMTPReview, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	review, err := readSMTP(ctx, tx, scope, false)
	if err != nil {
		return nil, err
	}
	last := &SMTPTestResult{}
	err = tx.QueryRowContext(ctx, `SELECT id::text,status,revision::text,created_at FROM uem_smtp_test_attempts WHERE settings_id=$1 AND tenant_id=$2 AND actor=$3 ORDER BY created_at DESC,id DESC LIMIT 1`, review.ID, scope.TenantID, actor).Scan(&last.ID, &last.Status, &last.Revision, &last.CreatedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		if last.Status == "attempted" {
			last.Status = "unconfirmed"
		}
		review.LastTest = last
	}
	if err = smtpAudit(ctx, tx, actor, scope, "settings.smtp.read", fmt.Sprint(review.ID), "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return review, nil
}

func (s *SMTPStore) Save(parent context.Context, actor string, scope access.Scope, id int64, revision string, cfg SMTPConfig, passwordAction, password string) error {
	parsed, err := uuid.Parse(revision)
	if err != nil || parsed.String() != revision || id <= 0 || !cfg.Valid() {
		return ErrInvalid
	}
	replace := false
	switch passwordAction {
	case "keep":
		if password != "" {
			return ErrInvalid
		}
	case "clear":
		if password != "" {
			return ErrInvalid
		}
		replace = true
	case "replace":
		if password == "" {
			return ErrInvalid
		}
		replace = true
	default:
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := readSMTP(ctx, tx, scope, true)
	if err != nil {
		return err
	}
	if current.ID != id {
		return ErrNotFound
	}
	if current.Revision != revision {
		return ErrConflict
	}
	if passwordAction == "replace" {
		password, err = legacysecret.Seal(password, s.key)
		if err != nil {
			return ErrSecret
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE settings SET smtp_server=$2,smtp_port=$3,smtp_user=$4,smtp_auth=$5,message_from=$6,smtp_encryption_type=$7,smtp_password=CASE WHEN $8 THEN $9 ELSE smtp_password END WHERE id=$1`, id, cfg.Server, cfg.Port, cfg.User, cfg.Auth, cfg.From, cfg.Encryption, replace, password); err != nil {
		return err
	}
	if err = smtpAudit(ctx, tx, actor, scope, "settings.smtp.update", fmt.Sprintf("%d/password/%s", id, passwordAction), "success"); err != nil {
		return err
	}
	return tx.Commit()
}
