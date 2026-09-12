package apple

import (
	"context"
	"time"
)

func (s *Store) VendorConfigured() bool { return s.vendor != nil }

// AttachVendorRequest verifies the vendor response against this request's public
// CSR under the same lock used for revocation and certificate replacement.
func (s *Store) AttachVendorRequest(ctx context.Context, tenant int, id string, encoded []byte, actor string) error {
	if s.vendor == nil {
		return ErrVendorNotConfigured
	}
	if len(encoded) == 0 || len(encoded) > MaxVendorPortalRequest {
		return ErrVendorRequest
	}
	tx, err := s.pushRequestTx(ctx, tenant, actor)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = livePushRequest(ctx, tx, tenant, id); err != nil {
		return err
	}
	var csr []byte
	if err = tx.QueryRowContext(ctx, `SELECT csr FROM mdm_apple_push_requests WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&csr); err != nil {
		return err
	}
	verified, err := s.vendor.VerifyPortalRequest(csr, encoded, time.Now())
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_push_requests SET vendor_request=$3,vendor_fingerprint=$4,vendor_expires_at=$5 WHERE tenant_id=$1 AND id=$2`, tenant, id, verified.Encoded, verified.Fingerprint, verified.ExpiresAt); err != nil {
		return err
	}
	if _, err = livePushRequest(ctx, tx, tenant, id); err != nil {
		return err
	}
	if err = audit(ctx, tx, tenant, actor, "apple.push_request.vendor_attach", id); err != nil {
		return err
	}
	return tx.Commit()
}

// VendorPortalRequest revalidates stored bytes, the live request and current
// operator pins before download. A previously saved response is not permanent
// trust in an expired or removed vendor credential.
func (s *Store) VendorPortalRequest(ctx context.Context, tenant int, id, actor string) ([]byte, error) {
	if s.vendor == nil {
		return nil, ErrVendorNotConfigured
	}
	tx, err := s.pushRequestTx(ctx, tenant, actor)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = livePushRequest(ctx, tx, tenant, id); err != nil {
		return nil, err
	}
	var csr, encoded []byte
	if err = tx.QueryRowContext(ctx, `SELECT csr,vendor_request FROM mdm_apple_push_requests WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&csr, &encoded); err != nil {
		return nil, err
	}
	if len(encoded) == 0 {
		return nil, ErrNotFound
	}
	verified, err := s.vendor.VerifyPortalRequest(csr, encoded, time.Now())
	if err != nil {
		return nil, err
	}
	if _, err = livePushRequest(ctx, tx, tenant, id); err != nil {
		return nil, err
	}
	if err = audit(ctx, tx, tenant, actor, "apple.push_request.vendor_download", id); err != nil {
		return nil, err
	}
	return verified.Encoded, tx.Commit()
}
