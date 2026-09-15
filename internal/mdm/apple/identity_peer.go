package apple

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type identityPeer struct {
	kind, renewalID string
	tokenUpdated    bool
}

// The caller holds the device row lock. Recheck the certificate actually
// presented over TLS inside the transaction that consumes its authority.
func (s *Store) deviceIdentityPeer(ctx context.Context, tx *sql.Tx, d *Device) (identityPeer, error) {
	if d == nil || d.peerFingerprint == "" || !time.Now().Before(d.peerExpiresAt) {
		return identityPeer{}, ErrUnauthorized
	}
	var active string
	var expires time.Time
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(certificate_fingerprint,''),certificate_expires_at FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND status IN ('authenticating','enrolled')`, d.ID, d.TenantID).Scan(&active, &expires); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return identityPeer{}, ErrUnauthorized
		}
		return identityPeer{}, err
	}
	if active == d.peerFingerprint && time.Now().Before(expires) {
		return identityPeer{kind: "active"}, nil
	}
	var peer identityPeer
	err := tx.QueryRowContext(ctx, `SELECT id,token_updated_at IS NOT NULL FROM mdm_apple_identity_renewals WHERE device_id=$1 AND tenant_id=$2 AND status='issued' AND base_fingerprint=$3 AND certificate_fingerprint=$4 AND certificate_expires_at>clock_timestamp()`, d.ID, d.TenantID, active, d.peerFingerprint).Scan(&peer.renewalID, &peer.tokenUpdated)
	if err == nil {
		peer.kind = "candidate"
		return peer, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return identityPeer{}, err
	}
	err = tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_identity_renewals WHERE device_id=$1 AND tenant_id=$2 AND status='confirmed' AND certificate_fingerprint=$3 AND base_fingerprint=$4 AND grace_until>clock_timestamp() AND base_expires_at>clock_timestamp()`, d.ID, d.TenantID, active, d.peerFingerprint).Scan(&peer.renewalID)
	if err == nil {
		peer.kind = "retired"
		return peer, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return identityPeer{}, err
	}
	return identityPeer{}, ErrUnauthorized
}

func (s *Store) requireActiveIdentity(ctx context.Context, tx *sql.Tx, d *Device) error {
	peer, err := s.deviceIdentityPeer(ctx, tx, d)
	if err != nil {
		return err
	}
	if peer.kind != "active" {
		return ErrUnauthorized
	}
	return nil
}
