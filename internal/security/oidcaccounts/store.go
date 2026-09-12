// Package oidcaccounts binds verified issuer/subject pairs to local accounts.
// Provider usernames and email addresses never select an existing account.
package oidcaccounts

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/open-uem/ent"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/mfaadmission"
)

var (
	ErrIdentity = errors.New("OpenID identity is not linked to an eligible account")
	ErrConflict = errors.New("OpenID account or configuration changed; reload before saving")
)

//go:embed migrations/001_bindings.sql
var schema string

type Store struct {
	db     *sql.DB
	access *access.Store
}

func NewStore(db *sql.DB, permissions *access.Store) (*Store, error) {
	if db == nil || permissions == nil {
		return nil, errors.New("OpenID account store requires database and permissions")
	}
	return &Store{db, permissions}, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627916)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS uem_oidc_migrations (name TEXT PRIMARY KEY)`); err != nil {
		return err
	}
	var applied bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_oidc_migrations WHERE name='001_bindings')`).Scan(&applied); err != nil {
		return err
	}
	if !applied {
		if _, err = tx.ExecContext(ctx, schema); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_oidc_migrations VALUES ('001_bindings')`); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, mfaadmission.Schema); err != nil {
		return err
	}
	return tx.Commit()
}

type Policy struct {
	Enabled                          bool
	Issuer, ClientID, Provider, Role string
	AutoCreate, AutoApprove          bool
}

func PolicyFrom(s *ent.Authentication) Policy {
	return Policy{s.UseOIDC, s.OIDCIssuerURL, s.OIDCClientID, s.OIDCProvider, s.OIDCRole, s.OIDCAutoCreateAccount, s.OIDCAutoApprove}
}

func readPolicy(ctx context.Context, tx *sql.Tx) (Policy, error) {
	var p Policy
	rows, err := tx.QueryContext(ctx, `SELECT COALESCE(use_oidc,false),COALESCE(oidc_issuer_url,''),COALESCE(oidc_client_id,''),COALESCE(oidc_provider,''),COALESCE(oidc_role,''),COALESCE(oidc_auto_create_account,false),COALESCE(oidc_auto_approve,false) FROM authentications FOR SHARE`)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	if !rows.Next() {
		return p, ErrConflict
	}
	if err = rows.Scan(&p.Enabled, &p.Issuer, &p.ClientID, &p.Provider, &p.Role, &p.AutoCreate, &p.AutoApprove); err != nil {
		return p, err
	}
	if rows.Next() {
		return p, ErrConflict
	}
	return p, rows.Err()
}

func validIdentity(issuer, subject string) bool {
	u, err := url.Parse(issuer)
	return err == nil && len(issuer) <= 2048 && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" &&
		len(subject) > 0 && len(subject) <= 255 && strings.IndexFunc(subject, func(r rune) bool { return r < 0x20 || r > 0x7e }) < 0
}

type Identity struct {
	Issuer, Subject, Name, Email, Phone string
	EmailVerified                       bool
}

// Resolve is called only after signature, nonce, UserInfo and role verification.
// Account creation and its permanent binding/audit commit in one transaction.
func (s *Store) Resolve(ctx context.Context, expected Policy, id Identity) (string, error) {
	if !validIdentity(id.Issuer, id.Subject) {
		return "", ErrIdentity
	}
	for _, value := range []string{id.Name, id.Email, id.Phone} {
		if len(value) > 1024 || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return "", ErrIdentity
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	current, err := readPolicy(ctx, tx)
	if err != nil {
		return "", err
	}
	if current != expected || !current.Enabled || current.Issuer != id.Issuer {
		return "", ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627916)`); err != nil {
		return "", err
	}
	var uid string
	var active bool
	err = tx.QueryRowContext(ctx, `SELECT user_id,active FROM uem_oidc_bindings WHERE issuer=$1 AND subject=$2`, id.Issuer, id.Subject).Scan(&uid, &active)
	if err == nil {
		var eligible bool
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE(openid,false) AND NOT COALESCE(passwd,false) AND register<>$2 FROM users WHERE uid=$1 FOR SHARE`, uid, nats.REGISTER_REVOKED).Scan(&eligible); err != nil {
			return "", err
		}
		if !active || !eligible {
			return "", ErrIdentity
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if !current.AutoCreate {
			return "", ErrIdentity
		}
		uid = "oidc-" + uuid.NewString()
		status := nats.REGISTER_IN_REVIEW
		if current.AutoApprove {
			status = nats.REGISTER_APPROVED
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO users(uid,name,email,phone,email_verified,register,openid,passwd,use2fa,created) VALUES($1,$2,$3,$4,$5,$6,true,false,false,now())`, uid, id.Name, id.Email, id.Phone, id.EmailVerified, status); err != nil {
			return "", err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_oidc_accounts(user_id) VALUES($1)`, uid); err != nil {
			return "", err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_oidc_bindings(issuer,subject,user_id,active) VALUES($1,$2,$3,true)`, id.Issuer, id.Subject, uid); err != nil {
			return "", err
		}
		if err = record(ctx, tx, uid, "identity-provider", "create", id.Issuer, id.Subject); err != nil {
			return "", err
		}
	} else {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return uid, nil
}

type Binding struct {
	Issuer, Subject string
	Active          bool
}
type Event struct {
	ID, Revision                   int64
	Actor, Action, Issuer, Subject string
	At                             time.Time
}
type Page struct {
	UserID, Name, Issuer, ClientID string
	Revision                       int64
	Eligible, Enabled              bool
	Bindings                       []Binding
	Events                         []Event
}

func (p *Page) CanLink() bool {
	if !p.Enabled || !p.Eligible {
		return false
	}
	for _, binding := range p.Bindings {
		if binding.Active && binding.Issuer == p.Issuer {
			return false
		}
	}
	return true
}

func (s *Store) Page(ctx context.Context, actor, uid string) (*Page, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.access.AuthorizeTransaction(ctx, tx, actor, access.ManageAccess, access.Scope{}); err != nil {
		return nil, err
	}
	p, err := readPolicy(ctx, tx)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared(684627916)`); err != nil {
		return nil, err
	}
	page := &Page{UserID: uid, Issuer: p.Issuer, ClientID: p.ClientID, Enabled: p.Enabled}
	err = tx.QueryRowContext(ctx, `SELECT u.name,COALESCE(u.openid,false) AND NOT COALESCE(u.passwd,false) AND u.register<>$2,COALESCE(a.revision,0) FROM users u LEFT JOIN uem_oidc_accounts a ON a.user_id=u.uid WHERE u.uid=$1`, uid, nats.REGISTER_REVOKED).Scan(&page.Name, &page.Eligible, &page.Revision)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT issuer,subject,active FROM uem_oidc_bindings WHERE user_id=$1 ORDER BY issuer,subject LIMIT 101`, uid)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var b Binding
		if err = rows.Scan(&b.Issuer, &b.Subject, &b.Active); err != nil {
			rows.Close()
			return nil, err
		}
		page.Bindings = append(page.Bindings, b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(page.Bindings) > 100 {
		return nil, ErrConflict
	}
	rows, err = tx.QueryContext(ctx, `SELECT id,revision,actor,action,issuer,subject,occurred_at FROM uem_oidc_audit WHERE user_id=$1 ORDER BY revision DESC LIMIT 25`, uid)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var e Event
		if err = rows.Scan(&e.ID, &e.Revision, &e.Actor, &e.Action, &e.Issuer, &e.Subject, &e.At); err != nil {
			rows.Close()
			return nil, err
		}
		page.Events = append(page.Events, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}

// Change never transfers a pair to another account. Disabled pairs remain
// reserved, so automatic registration cannot bypass an administrator's denial.
func (s *Store) Change(ctx context.Context, actor, uid, issuer, clientID, subject, action string, expected int64) error {
	if !validIdentity(issuer, subject) || expected < 0 {
		return ErrIdentity
	}
	if action != "link" && action != "enable" && action != "disable" {
		return ErrIdentity
	}
	if actor == uid && action == "disable" {
		return ErrIdentity
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.access.AuthorizeTransaction(ctx, tx, actor, access.ManageAccess, access.Scope{}); err != nil {
		return err
	}
	p, err := readPolicy(ctx, tx)
	if err != nil {
		return err
	}
	if !p.Enabled || p.Issuer != issuer || p.ClientID != clientID {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627916)`); err != nil {
		return err
	}
	var eligible bool
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(openid,false) AND NOT COALESCE(passwd,false) AND register<>$2 FROM users WHERE uid=$1 FOR SHARE`, uid, nats.REGISTER_REVOKED).Scan(&eligible); err != nil {
		return err
	}
	if !eligible && action != "disable" {
		return ErrIdentity
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_oidc_accounts(user_id) VALUES($1) ON CONFLICT DO NOTHING`, uid); err != nil {
		return err
	}
	var revision int64
	if err = tx.QueryRowContext(ctx, `SELECT revision FROM uem_oidc_accounts WHERE user_id=$1`, uid).Scan(&revision); err != nil {
		return err
	}
	if revision != expected {
		return ErrConflict
	}
	var owner string
	var active bool
	err = tx.QueryRowContext(ctx, `SELECT user_id,active FROM uem_oidc_bindings WHERE issuer=$1 AND subject=$2`, issuer, subject).Scan(&owner, &active)
	if action == "link" {
		if !errors.Is(err, sql.ErrNoRows) {
			if err != nil {
				return err
			}
			return ErrConflict
		}
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM uem_oidc_bindings WHERE user_id=$1`, uid).Scan(&count); err != nil {
			return err
		}
		if count >= 100 {
			return ErrConflict
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_oidc_bindings(issuer,subject,user_id,active) VALUES($1,$2,$3,true)`, issuer, subject, uid); err != nil {
			return ErrConflict
		}
	} else {
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrConflict
			}
			return err
		}
		if owner != uid || active == (action == "enable") {
			return ErrConflict
		}
		if _, err = tx.ExecContext(ctx, `UPDATE uem_oidc_bindings SET active=$3 WHERE issuer=$1 AND subject=$2`, issuer, subject, action == "enable"); err != nil {
			return ErrConflict
		}
	}
	if err = record(ctx, tx, uid, actor, action, issuer, subject); err != nil {
		return err
	}
	return tx.Commit()
}

func record(ctx context.Context, tx *sql.Tx, uid, actor, action, issuer, subject string) error {
	_, err := tx.ExecContext(ctx, `WITH changed AS (UPDATE uem_oidc_accounts SET revision=revision+1 WHERE user_id=$1 RETURNING revision) INSERT INTO uem_oidc_audit(user_id,revision,actor,action,issuer,subject) SELECT $1,revision,$2,$3,$4,$5 FROM changed`, uid, actor, action, issuer, subject)
	return err
}
