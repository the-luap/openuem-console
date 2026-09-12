package windows

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// EnrollmentInvitation contains console metadata only. Its issued random secret
// is returned once in a separate redacted credential object and is never stored.
type EnrollmentInvitation struct {
	ID string
	access.Scope
	Username          string
	CreatedBy         string
	CreatedByRevision int
	CreatedAt         time.Time
	ExpiresAt         time.Time
	RevokedAt         *time.Time
	ConsumedAt        *time.Time
}

const invitationColumns = `id,tenant_id,site_id,username,created_by,created_by_revision,created_at,expires_at,revoked_at,consumed_at`

// Match the discovery account-hint limit so issued credentials can traverse the
// complete discovery flow as well as the more permissive XCEP wire grammar.
const MaxEnrollmentUsernameBytes = 320

func scanInvitation(row *sql.Row) (*EnrollmentInvitation, error) {
	var invitation EnrollmentInvitation
	err := row.Scan(&invitation.ID, &invitation.TenantID, &invitation.SiteID, &invitation.Username, &invitation.CreatedBy, &invitation.CreatedByRevision, &invitation.CreatedAt, &invitation.ExpiresAt, &invitation.RevokedAt, &invitation.ConsumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &invitation, nil
}

func validEnrollmentUsername(username string) bool {
	return len(username) > 0 && len(username) <= MaxEnrollmentUsernameBytes && utf8.ValidString(username) && strings.TrimSpace(username) == username && strings.IndexFunc(username, unicode.IsControl) < 0
}

func canonicalInvitationID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.String() == id
}

// The 256-bit secret is the HMAC key. Including immutable scope and issuer
// metadata prevents a copied verifier from authorizing a different invitation.
func invitationDigest(secret []byte, invitation EnrollmentInvitation) []byte {
	h := hmac.New(sha256.New, secret)
	fmt.Fprintf(h, "openuem.windows.invitation.v1\x00%s\x00%d\x00%d\x00%s\x00%s\x00%d", invitation.ID, invitation.TenantID, invitation.SiteID, invitation.Username, invitation.CreatedBy, invitation.CreatedByRevision)
	return h.Sum(nil)
}

func decodeEnrollmentPassword(password string) (string, []byte, error) {
	// This generated password is distinct from any directory or console password.
	if len(password) != 6+36+1+43 || !strings.HasPrefix(password, "owin1.") {
		return "", nil, ErrCredential
	}
	parts := strings.Split(password, ".")
	if len(parts) != 3 || !canonicalInvitationID(parts[1]) {
		return "", nil, ErrCredential
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != parts[2] {
		return "", nil, ErrCredential
	}
	return parts[1], secret, nil
}

// CreateEnrollmentInvitation authenticates the current console actor inside the
// same transaction as scope validation, insertion and audit. A failed operation
// never returns a credential. Enrollment always has one concrete site.
func (s *Store) CreateEnrollmentInvitation(ctx context.Context, actor string, scope access.Scope, username string, validFor time.Duration) (*EnrollmentInvitation, *UsernameCredential, error) {
	if !validEnrollmentUsername(username) || validFor < time.Minute || validFor > 24*time.Hour || validFor%time.Second != 0 {
		return nil, nil, ErrInvitation
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeInvitationConsole(ctx, tx, actor, scope); err != nil {
		return nil, nil, err
	}
	invitation := EnrollmentInvitation{ID: uuid.NewString(), Scope: scope, Username: username, CreatedBy: actor}
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM uem_access_revisions WHERE user_id=$1`, actor).Scan(&invitation.CreatedByRevision); err != nil {
		return nil, nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, nil, err
	}
	defer clear(secret)
	digest := invitationDigest(secret, invitation)
	row := tx.QueryRowContext(ctx, `WITH stamp AS (SELECT clock_timestamp() AS at) INSERT INTO mdm_windows_invitations(id,tenant_id,site_id,username,credential_digest,created_by,created_by_revision,created_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,at,at+($8::bigint*INTERVAL '1 second') FROM stamp RETURNING `+invitationColumns, invitation.ID, scope.TenantID, scope.SiteID, username, digest, actor, invitation.CreatedByRevision, int64(validFor/time.Second))
	stored, err := scanInvitation(row)
	if err != nil {
		return nil, nil, err
	}
	if err := auditInvitation(ctx, tx, *stored, actor, "invitation.created"); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return stored, &UsernameCredential{Username: username, Password: "owin1." + invitation.ID + "." + base64.RawURLEncoding.EncodeToString(secret)}, nil
}

func (s *Store) EnrollmentInvitation(ctx context.Context, actor string, scope access.Scope, id string) (*EnrollmentInvitation, error) {
	if !canonicalInvitationID(id) {
		return nil, ErrInvitation
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeInvitationConsole(ctx, tx, actor, scope); err != nil {
		return nil, err
	}
	invitation, err := scanInvitation(tx.QueryRowContext(ctx, `SELECT `+invitationColumns+` FROM mdm_windows_invitations WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR SHARE`, id, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, err
	}
	if err := auditInvitation(ctx, tx, *invitation, actor, "invitation.read"); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return invitation, nil
}

func (s *Store) RevokeEnrollmentInvitation(ctx context.Context, actor string, scope access.Scope, id string) error {
	if !canonicalInvitationID(id) {
		return ErrInvitation
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.authorizeInvitationConsole(ctx, tx, actor, scope); err != nil {
		return err
	}
	invitation, err := scanInvitation(tx.QueryRowContext(ctx, `SELECT `+invitationColumns+` FROM mdm_windows_invitations WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR UPDATE`, id, scope.TenantID, scope.SiteID))
	if err != nil {
		return err
	}
	if invitation.RevokedAt == nil {
		if _, err := tx.ExecContext(ctx, `UPDATE mdm_windows_invitations SET revoked_at=clock_timestamp() WHERE id=$1`, id); err != nil {
			return err
		}
		if err := auditInvitation(ctx, tx, *invitation, actor, "invitation.revoked"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CheckPolicyCredential authorizes only the current read-only policy request.
// It does not reserve or consume the invitation and is not an issuance grant.
// WSTEP rechecks this credential in its own issuance/replay transaction.
func (s *Store) CheckPolicyCredential(ctx context.Context, credential UsernameCredential) (*EnrollmentInvitation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	invitation, err := s.authorizeEnrollmentCredential(ctx, tx, credential, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return invitation, nil
}

func (s *Store) authorizeEnrollmentCredential(ctx context.Context, tx *sql.Tx, credential UsernameCredential, consuming bool) (*EnrollmentInvitation, error) {
	use := credentialPolicyRead
	if consuming {
		use = credentialFirstIssue
	}
	return s.authorizeEnrollmentCredentialUse(ctx, tx, credential, use)
}

type enrollmentCredentialUse uint8

const (
	credentialPolicyRead enrollmentCredentialUse = iota
	credentialFirstIssue
	credentialIssueOrReplay
)

func (s *Store) authorizeEnrollmentCredentialUse(ctx context.Context, tx *sql.Tx, credential UsernameCredential, use enrollmentCredentialUse) (*EnrollmentInvitation, error) {
	if tx == nil || !validEnrollmentUsername(credential.Username) {
		return nil, ErrCredential
	}
	id, secret, err := decodeEnrollmentPassword(credential.Password)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	// Read a verifier before taking permission/site locks. Invalid random probes
	// must not hold the shared administrative permission lock.
	var invitation EnrollmentInvitation
	var digest []byte
	err = tx.QueryRowContext(ctx, `SELECT id,tenant_id,site_id,username,created_by,created_by_revision,credential_digest FROM mdm_windows_invitations WHERE id=$1`, id).Scan(&invitation.ID, &invitation.TenantID, &invitation.SiteID, &invitation.Username, &invitation.CreatedBy, &invitation.CreatedByRevision, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCredential
	}
	if err != nil {
		return nil, err
	}
	if credential.Username != invitation.Username || !hmac.Equal(digest, invitationDigest(secret, invitation)) {
		return nil, ErrCredential
	}
	if err := s.authorizeInvitationConsole(ctx, tx, invitation.CreatedBy, invitation.Scope); err != nil {
		if errors.Is(err, access.ErrDenied) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvitation) {
			return nil, ErrCredential
		}
		return nil, err
	}
	var revision int
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM uem_access_revisions WHERE user_id=$1`, invitation.CreatedBy).Scan(&revision); err != nil {
		return nil, err
	}
	if revision != invitation.CreatedByRevision {
		return nil, ErrCredential
	}
	lock := " FOR SHARE"
	if use != credentialPolicyRead {
		lock = " FOR UPDATE"
	}
	current, err := scanInvitation(tx.QueryRowContext(ctx, `SELECT `+invitationColumns+` FROM mdm_windows_invitations WHERE id=$1 AND created_at<=clock_timestamp() AND expires_at>clock_timestamp() AND revoked_at IS NULL AND ($2 OR consumed_at IS NULL)`+lock, id, use == credentialIssueOrReplay))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrCredential
	}
	if err != nil {
		return nil, err
	}
	// Recheck the database clock after any wait for the row lock. A transaction
	// start timestamp or a predicate evaluated before waiting can be stale.
	if err := activeEnrollmentInvitationUse(ctx, tx, id, use == credentialIssueOrReplay); err != nil {
		return nil, err
	}
	return current, nil
}

// The invitation and its scope/permissions must already be locked by the caller.
func activeEnrollmentInvitation(ctx context.Context, tx *sql.Tx, id string) error {
	return activeEnrollmentInvitationUse(ctx, tx, id, false)
}

func activeEnrollmentInvitationUse(ctx context.Context, tx *sql.Tx, id string, allowReplay bool) error {
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT created_at<=clock_timestamp() AND expires_at>clock_timestamp() AND revoked_at IS NULL AND (consumed_at IS NULL OR ($2 AND consumed_at<=clock_timestamp() AND consumed_at>clock_timestamp()-INTERVAL '10 minutes')) FROM mdm_windows_invitations WHERE id=$1`, id, allowReplay).Scan(&active); err != nil {
		return err
	}
	if !active {
		return ErrCredential
	}
	return nil
}

// A callback failure or late expiry rolls back both work and consumption. This
// helper exercises the first-use transaction boundary; WSTEP also supports a
// strictly bound durable response replay through credentialIssueOrReplay.
func (s *Store) withEnrollmentCredential(ctx context.Context, credential UsernameCredential, issue func(context.Context, *sql.Tx, EnrollmentInvitation) error) error {
	if issue == nil {
		return ErrInvitation
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	invitation, err := s.authorizeEnrollmentCredential(ctx, tx, credential, true)
	if err != nil {
		return err
	}
	if err := issue(ctx, tx, *invitation); err != nil {
		return err
	}
	if err := consumeEnrollmentInvitation(ctx, tx, *invitation); err != nil {
		return err
	}
	return tx.Commit()
}

func consumeEnrollmentInvitation(ctx context.Context, tx *sql.Tx, invitation EnrollmentInvitation) error {
	result, err := tx.ExecContext(ctx, `WITH stamp AS (SELECT clock_timestamp() AS at) UPDATE mdm_windows_invitations SET consumed_at=stamp.at FROM stamp WHERE id=$1 AND created_at<=stamp.at AND expires_at>stamp.at AND revoked_at IS NULL AND consumed_at IS NULL`, invitation.ID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrCredential
	}
	return auditInvitation(ctx, tx, invitation, "windows-enrollment", "invitation.consumed")
}
