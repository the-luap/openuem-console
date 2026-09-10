package windows

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type CertificateHealthOptions struct {
	Search        string
	Filter        string
	WithinDays    int
	Offset, Limit int
}

func (o CertificateHealthOptions) validate() error {
	if !validConsolePage(o.Offset, o.Limit) || o.WithinDays < 1 || o.WithinDays > 365 || len(o.Search) > 128 || !utf8.ValidString(o.Search) || strings.IndexFunc(o.Search, unicode.IsControl) >= 0 || !slices.Contains([]string{"all", "attention", "renewal_due", "expires_soon", "expired", "pending", "retired"}, o.Filter) {
		return ErrConsoleInput
	}
	return nil
}

type CertificateAuthorityHealth struct {
	ID                                              string    `json:"-" xml:"-" yaml:"-"`
	FingerprintSHA256                               string    `json:"-" xml:"-" yaml:"-"`
	State                                           string    `json:"-" xml:"-" yaml:"-"`
	NotBefore, CreatedAt, ExpiresAt, IssuanceEndsAt time.Time `json:"-" xml:"-" yaml:"-"`
	ValiditySeconds, RenewalSeconds                 int64     `json:"-" xml:"-" yaml:"-"`
}

type DeviceCertificateHealth struct {
	Device             DeviceMetadata              `json:"-" xml:"-" yaml:"-"`
	Current            RenewalCertificateMetadata  `json:"-" xml:"-" yaml:"-"`
	CurrentState       string                      `json:"-" xml:"-" yaml:"-"`
	RenewalOpensAt     time.Time                   `json:"-" xml:"-" yaml:"-"`
	ConfirmedRenewalID string                      `json:"-" xml:"-" yaml:"-"`
	Pending            *CertificateRenewal         `json:"-" xml:"-" yaml:"-"`
	Replacement        *RenewalCertificateMetadata `json:"-" xml:"-" yaml:"-"`
	ReplacementState   string                      `json:"-" xml:"-" yaml:"-"`
}

type CertificateHealthReport struct {
	Scope      access.Scope                `json:"-" xml:"-" yaml:"-"`
	AssessedAt time.Time                   `json:"-" xml:"-" yaml:"-"`
	Authority  *CertificateAuthorityHealth `json:"-" xml:"-" yaml:"-"`
	Devices    []DeviceCertificateHealth   `json:"-" xml:"-" yaml:"-"`
}

func (CertificateAuthorityHealth) String() string     { return "[protected Windows issuer health]" }
func (v CertificateAuthorityHealth) GoString() string { return v.String() }
func (DeviceCertificateHealth) String() string        { return "[protected Windows certificate health]" }
func (v DeviceCertificateHealth) GoString() string    { return v.String() }
func (CertificateHealthReport) String() string {
	return "[protected Windows certificate health report]"
}
func (v CertificateHealthReport) GoString() string { return v.String() }

func certificateTimeState(now, notBefore, expires time.Time, revoked *time.Time) string {
	if revoked != nil {
		return "revoked"
	}
	if now.Before(notBefore) {
		return "not_yet_valid"
	}
	if !now.Before(expires) {
		return "expired"
	}
	return "valid"
}
func currentCertificateHealth(now, notBefore, expires, renewalOpens time.Time, revoked, retired *time.Time, withinDays int) string {
	if retired != nil {
		return "retired"
	}
	state := certificateTimeState(now, notBefore, expires, revoked)
	if state != "valid" {
		return state
	}
	if !now.Before(renewalOpens) {
		return "renewal_due"
	}
	if !expires.After(now.Add(time.Duration(withinDays) * 24 * time.Hour)) {
		return "expires_soon"
	}
	return "valid"
}
func authorityHealthState(now time.Time, a CertificateAuthorityHealth, withinDays int) string {
	state := certificateTimeState(now, a.NotBefore, a.ExpiresAt, nil)
	if state != "valid" {
		return state
	}
	if now.Before(a.CreatedAt) {
		return "not_yet_valid"
	}
	if !now.Before(a.IssuanceEndsAt) {
		return "issuance_unavailable"
	}
	if !a.IssuanceEndsAt.After(now.Add(time.Duration(withinDays) * 24 * time.Hour)) {
		return "issuance_ending"
	}
	return "available"
}

const certificateHealthPending = `EXISTS(SELECT 1 FROM mdm_windows_certificate_renewals pending WHERE pending.device_id=d.id AND pending.tenant_id=d.tenant_id AND pending.site_id=d.site_id AND pending.phase='pending')`
const certificateHealthFilter = ` AND CASE $4
 WHEN 'all' THEN true
 WHEN 'retired' THEN d.revoked_at IS NOT NULL
 WHEN 'pending' THEN d.revoked_at IS NULL AND ` + certificateHealthPending + `
 WHEN 'expired' THEN d.revoked_at IS NULL AND c.expires_at<=$5
 WHEN 'expires_soon' THEN d.revoked_at IS NULL AND c.revoked_at IS NULL AND c.expires_at>$5 AND c.expires_at<=$6
 WHEN 'renewal_due' THEN d.revoked_at IS NULL AND c.revoked_at IS NULL AND c.expires_at>$5 AND c.expires_at-make_interval(secs=>a.renewal_seconds::double precision)<=$5
 WHEN 'attention' THEN d.revoked_at IS NULL AND (c.issued_at>$5 OR d.created_at>$5 OR c.revoked_at IS NOT NULL OR c.expires_at<=$6 OR c.expires_at-make_interval(secs=>a.renewal_seconds::double precision)<=$5 OR ` + certificateHealthPending + ` OR $7::boolean)
 ELSE false END `

// CertificateHealth reports the current confirmed generation and an independent
// pending replacement. The timestamp is the database time used for every expiry
// comparison, not a claim of connectivity, scheduled renewal or local cleanup.
func (s *Store) CertificateHealth(ctx context.Context, actor string, scope access.Scope, options CertificateHealthOptions) (*CertificateHealthReport, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// ReadDevices validates and locks either the concrete site or organization.
	// Its permission lock remains held while the stronger certificate grant is
	// checked. An all-sites read needs an organization-wide grant.
	if err = s.authorizeConsole(ctx, tx, actor, scope, access.ReadDevices); err != nil {
		return nil, err
	}
	if err = s.permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageCertificates, scope); err != nil {
		return nil, err
	}
	report := &CertificateHealthReport{Scope: scope, Devices: []DeviceCertificateHealth{}}
	a, err := scanAuthority(tx.QueryRowContext(ctx, `SELECT `+authorityColumns+` FROM mdm_windows_authorities WHERE tenant_id=$1 FOR SHARE`, scope.TenantID))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if a != nil {
		var encrypted []byte
		if err = tx.QueryRowContext(ctx, `SELECT encrypted_key FROM mdm_windows_authorities WHERE id=$1 AND tenant_id=$2`, a.ID, scope.TenantID).Scan(&encrypted); err != nil {
			return nil, err
		}
		signer, err := s.authenticateAuthority(*a, encrypted)
		if err != nil {
			return nil, err
		}
		report.Authority = &CertificateAuthorityHealth{ID: a.ID, FingerprintSHA256: a.FingerprintSHA256, NotBefore: signer.certificate.NotBefore, CreatedAt: a.CreatedAt, ExpiresAt: signer.certificate.NotAfter, IssuanceEndsAt: signer.certificate.NotAfter.Add(-time.Duration(a.ValiditySeconds)*time.Second - 5*time.Minute), ValiditySeconds: a.ValiditySeconds, RenewalSeconds: a.RenewalSeconds}
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&report.AssessedAt); err != nil {
		return nil, err
	}
	if report.Authority != nil {
		report.Authority.State = authorityHealthState(report.AssessedAt, *report.Authority, options.WithinDays)
		warningEnd := report.AssessedAt.Add(time.Duration(options.WithinDays) * 24 * time.Hour)
		rows, err := tx.QueryContext(ctx, `SELECT d.id,c.id,d.site_id`+deviceMetadataJoin+`JOIN mdm_windows_authorities a ON a.id=c.authority_id AND a.tenant_id=d.tenant_id WHERE d.tenant_id=$1 AND ($2::bigint=0 OR d.site_id=$2) AND (position(lower($3) in lower(d.device_name))>0 OR position(lower($3) in d.id::text)>0)`+certificateHealthFilter+`ORDER BY (d.revoked_at IS NOT NULL),c.expires_at,d.id LIMIT $8 OFFSET $9 FOR SHARE OF d,c,e,site,a`, scope.TenantID, scope.SiteID, options.Search, options.Filter, report.AssessedAt, warningEnd, report.Authority.State != "available", options.Limit, options.Offset)
		if err != nil {
			return nil, err
		}
		type selected struct {
			device, certificate string
			site                int
		}
		devices := []selected{}
		seen := map[string]bool{}
		for rows.Next() {
			var d selected
			if err = rows.Scan(&d.device, &d.certificate, &d.site); err != nil {
				rows.Close()
				return nil, err
			}
			if seen[d.device] {
				rows.Close()
				return nil, ErrAuthoritySecret
			}
			seen[d.device] = true
			devices = append(devices, d)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		for _, d := range devices {
			health, err := s.deviceCertificateHealth(ctx, tx, access.Scope{TenantID: scope.TenantID, SiteID: d.site}, d.device, d.certificate, *a, report.AssessedAt, options.WithinDays, actor)
			if err != nil {
				return nil, err
			}
			report.Devices = append(report.Devices, *health)
		}
	}
	if err = auditWindowsConsole(ctx, tx, actor, scope, "certificate_health.read", ""); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return report, nil
}

func (s *Store) deviceCertificateHealth(ctx context.Context, tx *sql.Tx, scope access.Scope, deviceID, certificateID string, authority EnrollmentAuthority, asOf time.Time, withinDays int, actor string) (*DeviceCertificateHealth, error) {
	var count int
	var selectedID string
	if err := tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(min(c.id::text),'')`+deviceMetadataJoin+`WHERE d.id=$1 AND d.tenant_id=$2 AND d.site_id=$3`, deviceID, scope.TenantID, scope.SiteID).Scan(&count, &selectedID); err != nil {
		return nil, err
	}
	// The selection may have waited on a concurrent confirmation. Never present
	// its superseded certificate as the current generation after acquiring locks.
	if count != 1 || selectedID != certificateID {
		return nil, ErrCSPConflict
	}
	device, err := scanDeviceMetadata(tx.QueryRowContext(ctx, `SELECT `+deviceMetadataColumns+deviceMetadataJoin+`WHERE d.id=$1 AND d.tenant_id=$2 AND d.site_id=$3`, deviceID, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, err
	}
	certificate, _, err := s.renewalCertificate(ctx, tx, &storedCertificateRenewal{CertificateRenewal: CertificateRenewal{DeviceID: deviceID, Scope: scope}}, certificateID)
	if err != nil {
		return nil, err
	}
	if certificate.identity.AuthorityID != authority.ID || !device.CertificateExpiresAt.Equal(certificate.certificate.NotAfter) || device.FingerprintSHA256 != certificate.identity.FingerprintSHA256 {
		return nil, ErrAuthoritySecret
	}
	health := &DeviceCertificateHealth{Device: *device, Current: RenewalCertificateMetadata{ID: certificateID, AuthorityID: authority.ID, FingerprintSHA256: certificate.identity.FingerprintSHA256, IssuedAt: certificate.issued, ExpiresAt: certificate.certificate.NotAfter, RevokedAt: device.CertificateRevokedAt}}
	health.RenewalOpensAt = certificate.certificate.NotAfter.Add(-time.Duration(authority.RenewalSeconds) * time.Second)
	readyAt := certificate.certificate.NotBefore
	for _, earliest := range []time.Time{certificate.issued, certificate.deviceCreated} {
		if earliest.After(readyAt) {
			readyAt = earliest
		}
	}
	health.CurrentState = currentCertificateHealth(asOf, readyAt, certificate.certificate.NotAfter, health.RenewalOpensAt, device.CertificateRevokedAt, device.RevokedAt, withinDays)
	var anchor string
	if err = tx.QueryRowContext(ctx, `SELECT certificate_id FROM mdm_windows_enrollments WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3`, deviceID, scope.TenantID, scope.SiteID).Scan(&anchor); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+renewalColumns+` FROM mdm_windows_certificate_renewals WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND ((renewed_certificate_id=$4 AND phase='confirmed') OR phase='pending') ORDER BY created_at,id FOR SHARE`, deviceID, scope.TenantID, scope.SiteID, certificateID)
	if err != nil {
		return nil, err
	}
	renewals := []*storedCertificateRenewal{}
	for rows.Next() {
		r, err := scanCertificateRenewal(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		renewals = append(renewals, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, r := range renewals {
		if _, err = s.openCertificateRenewal(ctx, tx, r); err != nil {
			return nil, err
		}
		if r.Phase == "confirmed" {
			if health.ConfirmedRenewalID != "" || certificateID == anchor {
				return nil, ErrAuthoritySecret
			}
			var revoked *time.Time
			if err = tx.QueryRowContext(ctx, `SELECT revoked_at FROM mdm_windows_device_certificates WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4`, r.SourceCertificateID, deviceID, scope.TenantID, scope.SiteID).Scan(&revoked); err != nil {
				return nil, err
			}
			if revoked == nil || r.CompletedAt == nil || !revoked.Equal(*r.CompletedAt) {
				return nil, ErrAuthoritySecret
			}
			health.ConfirmedRenewalID = r.ID
		} else {
			if health.Pending != nil || r.SourceCertificateID != certificateID {
				return nil, ErrAuthoritySecret
			}
			replacement, _, err := s.renewalCertificate(ctx, tx, r, r.RenewedCertificateID)
			if err != nil {
				return nil, err
			}
			var revoked *time.Time
			if err = tx.QueryRowContext(ctx, `SELECT revoked_at FROM mdm_windows_device_certificates WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4`, r.RenewedCertificateID, deviceID, scope.TenantID, scope.SiteID).Scan(&revoked); err != nil {
				return nil, err
			}
			health.Pending = &r.CertificateRenewal
			health.Replacement = &RenewalCertificateMetadata{ID: r.RenewedCertificateID, AuthorityID: replacement.identity.AuthorityID, FingerprintSHA256: replacement.identity.FingerprintSHA256, IssuedAt: replacement.issued, ExpiresAt: replacement.certificate.NotAfter, RevokedAt: revoked}
			health.ReplacementState = certificateTimeState(asOf, replacement.certificate.NotBefore, replacement.certificate.NotAfter, revoked)
		}
		if err = auditCertificateRenewal(ctx, tx, r, actor, "renewal.read"); err != nil {
			return nil, err
		}
	}
	if certificateID != anchor && health.ConfirmedRenewalID == "" {
		return nil, ErrAuthoritySecret
	}
	if device.UnenrollmentReportedAt != nil {
		report, err := s.readUnenrollmentReport(ctx, tx, scope, deviceID)
		if err != nil {
			return nil, err
		}
		health.Device.Unenrollment = &report.UnenrollmentReport
		if err = auditUnenrollment(ctx, tx, report, actor, "unenrollment.read"); err != nil {
			return nil, err
		}
	}
	return health, nil
}
