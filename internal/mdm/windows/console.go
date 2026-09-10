package windows

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrConsoleInput = errors.New("invalid native Windows console request")

// DeviceMetadata is enrollment metadata, not proof of current online state,
// platform attestation, a completed management exchange or applied policy.
type DeviceMetadata struct {
	ID string
	access.Scope
	InvitationID, ReportedDeviceID, Name, EnrollmentType, OSVersion string
	OSEdition                                                       uint32
	CreatedAt, CertificateExpiresAt                                 time.Time
	RevokedAt, CertificateRevokedAt                                 *time.Time
	FingerprintSHA256                                               string
}

func (s *Store) authorizeConsole(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope, capability access.Capability) error {
	if actor == "" || len(actor) > 255 || !utf8.ValidString(actor) || strings.IndexFunc(actor, unicode.IsControl) >= 0 || scope.TenantID <= 0 || scope.SiteID < 0 || (scope.SiteID == 0 && capability != access.ReadDevices) {
		return ErrConsoleInput
	}
	if err := s.permissions.AuthorizeTransaction(ctx, tx, actor, capability, scope); err != nil {
		return err
	}
	if scope.SiteID == 0 {
		var id int
		err := tx.QueryRowContext(ctx, `SELECT id FROM tenants WHERE id=$1 FOR SHARE`, scope.TenantID).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	return lockEnrollmentScope(ctx, tx, scope)
}

func auditWindowsConsole(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope, action, id string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_console_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,$4,NULLIF($5,'')::uuid)`, scope.TenantID, scope.SiteID, actor, action, id)
	return err
}

func validConsolePage(offset, limit int) bool {
	return offset >= 0 && offset <= 100000 && limit >= 1 && limit <= 100
}

func (s *Store) EnrollmentInvitations(ctx context.Context, actor string, scope access.Scope, offset, limit int) ([]EnrollmentInvitation, error) {
	if !validConsolePage(offset, limit) {
		return nil, ErrConsoleInput
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeInvitationConsole(ctx, tx, actor, scope); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+invitationColumns+` FROM mdm_windows_invitations WHERE tenant_id=$1 AND site_id=$2 ORDER BY created_at DESC,id DESC LIMIT $3 OFFSET $4`, scope.TenantID, scope.SiteID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []EnrollmentInvitation{}
	for rows.Next() {
		var r EnrollmentInvitation
		if err := rows.Scan(&r.ID, &r.TenantID, &r.SiteID, &r.Username, &r.CreatedBy, &r.CreatedByRevision, &r.CreatedAt, &r.ExpiresAt, &r.RevokedAt, &r.ConsumedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := auditWindowsConsole(ctx, tx, actor, scope, "invitations.list", ""); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// EnrollmentAvailable discloses only issuer availability to a scoped enrollment
// operator. It does not export CA metadata/key material or authorize issuance.
func (s *Store) EnrollmentAvailable(ctx context.Context, actor string, scope access.Scope) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err := s.authorizeInvitationConsole(ctx, tx, actor, scope); err != nil {
		return false, err
	}
	_, err = s.enrollmentAuthority(ctx, tx, scope.TenantID)
	available := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrAuthorityUnavailable) {
		return false, err
	}
	if err := auditWindowsConsole(ctx, tx, actor, scope, "authority.status", ""); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return available, nil
}

const deviceMetadataColumns = `d.id,d.tenant_id,d.site_id,d.invitation_id,d.reported_device_id,d.device_name,d.enrollment_type,d.os_version,d.os_edition,d.created_at,d.revoked_at,c.expires_at,c.revoked_at,encode(c.fingerprint,'hex')`
const deviceMetadataJoin = ` FROM mdm_windows_devices d JOIN mdm_windows_enrollments e ON e.device_id=d.id AND e.invitation_id=d.invitation_id AND e.tenant_id=d.tenant_id AND e.site_id=d.site_id JOIN mdm_windows_device_certificates c ON c.id=e.certificate_id AND c.device_id=d.id AND c.tenant_id=d.tenant_id AND c.site_id=d.site_id JOIN sites site ON site.id=d.site_id AND site.tenant_sites=d.tenant_id `

func scanDeviceMetadata(row interface{ Scan(...any) error }) (*DeviceMetadata, error) {
	var d DeviceMetadata
	err := row.Scan(&d.ID, &d.TenantID, &d.SiteID, &d.InvitationID, &d.ReportedDeviceID, &d.Name, &d.EnrollmentType, &d.OSVersion, &d.OSEdition, &d.CreatedAt, &d.RevokedAt, &d.CertificateExpiresAt, &d.CertificateRevokedAt, &d.FingerprintSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) Devices(ctx context.Context, actor string, scope access.Scope, search string, offset, limit int) ([]DeviceMetadata, error) {
	if !validConsolePage(offset, limit) || len(search) > 128 || !utf8.ValidString(search) || strings.IndexFunc(search, unicode.IsControl) >= 0 {
		return nil, ErrConsoleInput
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeConsole(ctx, tx, actor, scope, access.ReadDevices); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+deviceMetadataColumns+deviceMetadataJoin+`WHERE d.tenant_id=$1 AND ($2::bigint=0 OR d.site_id=$2) AND (position(lower($3) in lower(d.device_name))>0 OR position(lower($3) in d.id::text)>0) ORDER BY d.created_at DESC,d.id DESC LIMIT $4 OFFSET $5 FOR SHARE OF d,c,e,site`, scope.TenantID, scope.SiteID, search, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []DeviceMetadata{}
	for rows.Next() {
		d, err := scanDeviceMetadata(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := auditWindowsConsole(ctx, tx, actor, scope, "devices.list", ""); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) Device(ctx context.Context, actor string, scope access.Scope, id string) (*DeviceMetadata, error) {
	if !canonicalInvitationID(id) {
		return nil, ErrConsoleInput
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeConsole(ctx, tx, actor, scope, access.ReadDevices); err != nil {
		return nil, err
	}
	d, err := scanDeviceMetadata(tx.QueryRowContext(ctx, `SELECT `+deviceMetadataColumns+deviceMetadataJoin+`WHERE d.id=$1 AND d.tenant_id=$2 AND d.site_id=$3 FOR SHARE OF d,c,e`, id, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, err
	}
	if err := auditWindowsConsole(ctx, tx, actor, scope, "device.read", id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d, nil
}

// RevokeDevice blocks subsequent enrollment replay, authentication and command
// admission for this identity. It preserves evidence and does not send an
// unenrollment command, remove profiles, revoke an agent or change host state.
func (s *Store) RevokeDevice(ctx context.Context, actor string, scope access.Scope, id string) error {
	if !canonicalInvitationID(id) {
		return ErrConsoleInput
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.authorizeConsole(ctx, tx, actor, scope, access.RevokeDevices); err != nil {
		return err
	}
	var revoked *time.Time
	err = tx.QueryRowContext(ctx, `SELECT revoked_at FROM mdm_windows_devices WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR UPDATE`, id, scope.TenantID, scope.SiteID).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if revoked == nil {
		if _, err := tx.ExecContext(ctx, `UPDATE mdm_windows_devices SET revoked_at=clock_timestamp() WHERE id=$1`, id); err != nil {
			return err
		}
		if err := auditWindowsConsole(ctx, tx, actor, scope, "device.revoked", id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
