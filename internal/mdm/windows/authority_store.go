package windows

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var (
	ErrAuthority            = errors.New("invalid native Windows enrollment authority")
	ErrAuthorityExists      = errors.New("native Windows enrollment authority is already configured")
	ErrAuthorityUnavailable = errors.New("native Windows enrollment authority is not ready to issue certificates")
)

type AuthorityOptions struct {
	Organization    string
	MinimumKeyBits  int
	ValiditySeconds int64
	RenewalSeconds  int64
}

func (o AuthorityOptions) validate() error {
	if o.Organization == "" || len(o.Organization) > 128 || strings.TrimSpace(o.Organization) != o.Organization || !utf8.ValidString(o.Organization) || strings.IndexFunc(o.Organization, unicode.IsControl) >= 0 {
		return ErrAuthority
	}
	if o.MinimumKeyBits != 2048 && o.MinimumKeyBits != 3072 && o.MinimumKeyBits != 4096 {
		return ErrAuthority
	}
	if o.ValiditySeconds < 86400 || o.ValiditySeconds > 365*86400 || o.RenewalSeconds < 3600 || o.RenewalSeconds >= o.ValiditySeconds {
		return ErrAuthority
	}
	return nil
}

// EnrollmentAuthority contains only public configuration and its root certificate.
// Its private key never enters console metadata or a policy response model.
type EnrollmentAuthority struct {
	ID       string
	TenantID int
	AuthorityOptions
	Certificate       []byte
	FingerprintSHA256 string
	CreatedBy         string
	CreatedAt         time.Time
	ExpiresAt         time.Time
}

const authorityColumns = `id,tenant_id,organization,minimum_key_bits,validity_seconds,renewal_seconds,certificate,created_by,created_at,expires_at`

func scanAuthority(row *sql.Row) (*EnrollmentAuthority, error) {
	var a EnrollmentAuthority
	err := row.Scan(&a.ID, &a.TenantID, &a.Organization, &a.MinimumKeyBits, &a.ValiditySeconds, &a.RenewalSeconds, &a.Certificate, &a.CreatedBy, &a.CreatedAt, &a.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if _, err := parseAuthorityCertificate(a); err != nil {
		return nil, err
	}
	hash := sha256.Sum256(a.Certificate)
	a.FingerprintSHA256 = hex.EncodeToString(hash[:])
	return &a, nil
}

func (s *Store) authorizeAuthorityConsole(ctx context.Context, tx *sql.Tx, actor string, tenant int, creating bool) error {
	if tenant <= 0 || actor == "" || len(actor) > 255 || !utf8.ValidString(actor) || strings.IndexFunc(actor, unicode.IsControl) >= 0 {
		return ErrAuthority
	}
	if err := s.permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageCertificates, access.Scope{TenantID: tenant}); err != nil {
		return err
	}
	lock := " FOR SHARE"
	if creating {
		lock = " FOR UPDATE"
	}
	var id int
	err := tx.QueryRowContext(ctx, `SELECT id FROM tenants WHERE id=$1`+lock, tenant).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func auditAuthority(ctx context.Context, tx *sql.Tx, a EnrollmentAuthority, actor, action string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_authority_audit(tenant_id,actor,action,authority_id) VALUES($1,$2,$3,$4)`, a.TenantID, actor, action, a.ID)
	return err
}

// InitializeAuthority creates one immutable issuer per organization. It never
// replaces an existing CA on retry or restart. Rotation must preserve old issuers
// and device bindings and is a separate, still unfinished lifecycle operation.
func (s *Store) InitializeAuthority(ctx context.Context, actor string, tenant int, options AuthorityOptions) (*EnrollmentAuthority, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeAuthorityConsole(ctx, tx, actor, tenant, true); err != nil {
		return nil, err
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_windows_authorities WHERE tenant_id=$1)`, tenant).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrAuthorityExists
	}
	a := EnrollmentAuthority{ID: uuid.NewString(), TenantID: tenant, AuthorityOptions: options, CreatedBy: actor}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	certificate, private, err := generateAuthorityCertificate(a, now)
	if err != nil {
		return nil, err
	}
	defer clear(private)
	a.Certificate = certificate
	parsed, err := x509.ParseCertificate(certificate)
	if err != nil {
		return nil, ErrAuthority
	}
	a.ExpiresAt = parsed.NotAfter
	encrypted, err := s.secrets.seal(private, authoritySecretPurpose(a))
	if err != nil {
		return nil, err
	}
	stored, err := scanAuthority(tx.QueryRowContext(ctx, `INSERT INTO mdm_windows_authorities(id,tenant_id,organization,minimum_key_bits,validity_seconds,renewal_seconds,certificate,encrypted_key,created_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+authorityColumns, a.ID, tenant, options.Organization, options.MinimumKeyBits, options.ValiditySeconds, options.RenewalSeconds, certificate, encrypted, actor, a.ExpiresAt))
	if err != nil {
		return nil, err
	}
	if err := auditAuthority(ctx, tx, *stored, actor, "authority.created"); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return stored, nil
}

func (s *Store) EnrollmentAuthority(ctx context.Context, actor string, tenant int) (*EnrollmentAuthority, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeAuthorityConsole(ctx, tx, actor, tenant, false); err != nil {
		return nil, err
	}
	a, err := scanAuthority(tx.QueryRowContext(ctx, `SELECT `+authorityColumns+` FROM mdm_windows_authorities WHERE tenant_id=$1 FOR SHARE`, tenant))
	if err != nil {
		return nil, err
	}
	if err := auditAuthority(ctx, tx, *a, actor, "authority.read"); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return a, nil
}

// Called only after the enrollment credential established and locked its scope.
func (s *Store) enrollmentAuthority(ctx context.Context, tx *sql.Tx, tenant int) (*authoritySigner, error) {
	a, err := scanAuthority(tx.QueryRowContext(ctx, `SELECT `+authorityColumns+` FROM mdm_windows_authorities WHERE tenant_id=$1 FOR SHARE`, tenant))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrAuthorityUnavailable
	}
	if err != nil {
		return nil, err
	}
	var encrypted []byte
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT encrypted_key,clock_timestamp() FROM mdm_windows_authorities WHERE id=$1 AND tenant_id=$2`, a.ID, tenant).Scan(&encrypted, &now); err != nil {
		return nil, err
	}
	return s.decryptAuthority(*a, encrypted, now)
}
