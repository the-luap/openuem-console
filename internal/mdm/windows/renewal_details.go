package windows

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

// RenewalCertificateMetadata contains public certificate lifecycle fields, never
// a private key, CSR, proof, bootstrap credential or provisioning document.
type RenewalCertificateMetadata struct {
	ID                string     `json:"-" xml:"-" yaml:"-"`
	AuthorityID       string     `json:"-" xml:"-" yaml:"-"`
	FingerprintSHA256 string     `json:"-" xml:"-" yaml:"-"`
	IssuedAt          time.Time  `json:"-" xml:"-" yaml:"-"`
	ExpiresAt         time.Time  `json:"-" xml:"-" yaml:"-"`
	RevokedAt         *time.Time `json:"-" xml:"-" yaml:"-"`
}

func (RenewalCertificateMetadata) String() string {
	return "[protected Windows renewal certificate metadata]"
}
func (v RenewalCertificateMetadata) GoString() string { return v.String() }

type CertificateRenewalDetail struct {
	Renewal     CertificateRenewal         `json:"-" xml:"-" yaml:"-"`
	Source      RenewalCertificateMetadata `json:"-" xml:"-" yaml:"-"`
	Replacement RenewalCertificateMetadata `json:"-" xml:"-" yaml:"-"`
	Resolution  string                     `json:"-" xml:"-" yaml:"-"`
}

func (CertificateRenewalDetail) String() string     { return "[protected Windows renewal detail]" }
func (v CertificateRenewalDetail) GoString() string { return v.String() }

// CertificateRenewalDetails authenticates the sealed lifecycle record and both
// certificates under the same scope/device locks as the audited metadata read.
func (s *Store) CertificateRenewalDetails(ctx context.Context, actor string, scope access.Scope, deviceID, renewalID string) (*CertificateRenewalDetail, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !canonicalInvitationID(renewalID) {
		return nil, ErrConsoleInput
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeRenewalConsole(ctx, tx, actor, scope, deviceID, false); err != nil {
		return nil, err
	}
	r, err := scanCertificateRenewal(tx.QueryRowContext(ctx, `SELECT `+renewalColumns+` FROM mdm_windows_certificate_renewals WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR SHARE`, renewalID, deviceID, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, err
	}
	record, err := s.openCertificateRenewal(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	detail := &CertificateRenewalDetail{Renewal: r.CertificateRenewal, Resolution: record.Resolution}
	for id, target := range map[string]*RenewalCertificateMetadata{r.SourceCertificateID: &detail.Source, r.RenewedCertificateID: &detail.Replacement} {
		// openCertificateRenewal has already verified DER, issuer, identity and
		// fingerprint while locking these immutable certificate fields.
		err := tx.QueryRowContext(ctx, `SELECT id,authority_id,encode(fingerprint,'hex'),issued_at,expires_at,revoked_at FROM mdm_windows_device_certificates WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR SHARE`, id, deviceID, scope.TenantID, scope.SiteID).Scan(&target.ID, &target.AuthorityID, &target.FingerprintSHA256, &target.IssuedAt, &target.ExpiresAt, &target.RevokedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAuthoritySecret
		}
		if err != nil {
			return nil, err
		}
	}
	if (r.Phase == "confirmed" && (detail.Source.RevokedAt == nil || !detail.Source.RevokedAt.Equal(*r.CompletedAt))) || (r.Phase == "canceled" && (detail.Replacement.RevokedAt == nil || !detail.Replacement.RevokedAt.Equal(*r.CompletedAt))) {
		return nil, ErrAuthoritySecret
	}
	if err := auditCertificateRenewal(ctx, tx, r, actor, "renewal.read"); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return detail, nil
}
