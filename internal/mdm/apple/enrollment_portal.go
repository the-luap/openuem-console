package apple

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"
)

const enrollmentBrowserCookie = "__Host-openuem-enrollment"

func enrollmentRetryBox(browser string) (*secretBox, error) {
	if !validEnrollmentToken(browser) {
		return nil, ErrUnauthorized
	}
	// Only its hash is stored. Database backups plus the server master key alone
	// cannot recover a retry profile after the browser's random secret is lost.
	return newSecretBox("openuem/apple/enrollment-retry/v1\x00" + browser)
}

func validEnrollmentToken(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func enrollmentCSRF(token, browser string) string {
	mac := hmac.New(sha256.New, []byte(browser))
	mac.Write([]byte("openuem/enrollment/form/v1\x00" + token))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// EnrollmentStatus contains only the information needed by the invited browser.
// It never exposes inventory, identifiers, push errors or device credentials.
type EnrollmentStatus struct {
	DeviceLockAllowed                 bool
	Platform                          Platform
	State, Organization, PublicOrigin string
	ExpiresAt                         time.Time
	DownloadsRemaining                int
}

func (s *Store) EnrollmentStatus(ctx context.Context, token, browser string) (*EnrollmentStatus, error) {
	if !validEnrollmentToken(token) {
		return nil, ErrNotFound
	}
	var state, browserHash string
	var inviteExpiry time.Time
	var downloadExpiry, statusExpiry sql.NullTime
	var downloads int
	var hasProfile bool
	result := &EnrollmentStatus{}
	err := s.db.QueryRowContext(ctx, `SELECT d.status,d.invite_expires_at,s.organization,s.public_url,COALESCE(c.browser_hash,''),c.download_expires_at,c.status_expires_at,COALESCE(c.download_count,0),c.profile IS NOT NULL,d.enrollment_platform,d.device_lock_allowed
	 FROM mdm_apple_devices d JOIN mdm_apple_settings s ON s.tenant_id=d.tenant_id
	 LEFT JOIN mdm_apple_enrollment_claims c ON c.device_id=d.id
	 WHERE d.invite_hash=$1 OR c.invite_hash=$1`, digest([]byte(token))).Scan(&state, &inviteExpiry, &result.Organization, &result.PublicOrigin, &browserHash, &downloadExpiry, &statusExpiry, &downloads, &hasProfile, &result.Platform, &result.DeviceLockAllowed)
	if err != nil {
		return nil, notFound(err)
	}
	if browserHash != "" && (!validEnrollmentToken(browser) || !hmac.Equal([]byte(browserHash), []byte(digest([]byte(browser))))) {
		result.State, result.Organization, result.Platform = "used", "", ""
		result.DeviceLockAllowed = false
		return result, nil
	}
	if statusExpiry.Valid && !time.Now().Before(statusExpiry.Time) {
		result.State, result.Organization, result.Platform = "expired", "", ""
		result.DeviceLockAllowed = false
		return result, nil
	}
	switch state {
	case "pending":
		result.State, result.ExpiresAt = "ready", inviteExpiry
		if !time.Now().Before(inviteExpiry) {
			result.State = "expired"
		}
	case "authenticating":
		result.State, result.ExpiresAt = "claimed", downloadExpiry.Time
		if hasProfile && downloadExpiry.Valid && time.Now().Before(downloadExpiry.Time) {
			result.DownloadsRemaining = 3 - downloads
		}
	case "enrolled", "revoked", "unenrolled":
		result.State = state
	default:
		return nil, ErrNotFound
	}
	return result, nil
}

// ClaimEnrollment authorizes one SCEP identity. Duplicate submissions from the
// same browser are idempotent; another browser cannot read the enrollment secret.
func (s *Store) ClaimEnrollment(ctx context.Context, token, browser string, platform ...Platform) error {
	if !validEnrollmentToken(browser) {
		return ErrUnauthorized
	}
	_, err := s.issueEnrollmentProfile(ctx, token, browser, platform...)
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	status, statusErr := s.EnrollmentStatus(ctx, token, browser)
	if statusErr != nil {
		return statusErr
	}
	if len(platform) == 1 && status.Platform != platform[0] {
		return ErrConflict
	}
	if status.State == "claimed" || status.State == "enrolled" {
		return nil
	}
	return ErrConflict
}

// DownloadEnrollment returns exactly the already-issued profile, never another
// identity. Lock the device before the claim to serialize with check-in/revoke.
func (s *Store) DownloadEnrollment(ctx context.Context, token, browser string) ([]byte, error) {
	if !validEnrollmentToken(token) || !validEnrollmentToken(browser) {
		return nil, ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var id string
	var tenant int
	err = tx.QueryRowContext(ctx, `SELECT d.id,d.tenant_id FROM mdm_apple_devices d JOIN mdm_apple_enrollment_claims c ON c.device_id=d.id WHERE c.invite_hash=$1 AND c.browser_hash=$2 AND d.status='authenticating' AND d.udid IS NULL FOR UPDATE OF d`, digest([]byte(token)), digest([]byte(browser))).Scan(&id, &tenant)
	if err != nil {
		return nil, notFound(err)
	}
	var encrypted []byte
	err = tx.QueryRowContext(ctx, `UPDATE mdm_apple_enrollment_claims SET download_count=download_count+1 WHERE device_id=$1 AND download_expires_at>now() AND download_count<3 AND profile IS NOT NULL RETURNING profile`, id).Scan(&encrypted)
	if err != nil {
		return nil, notFound(err)
	}
	data, err := s.secrets.open(encrypted, secretPurpose(tenant, id, "enrollment_retry"))
	if err != nil {
		return nil, err
	}
	box, err := enrollmentRetryBox(browser)
	if err != nil {
		return nil, err
	}
	data, err = box.open(data, secretPurpose(tenant, id, "enrollment_retry"))
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_enrollment_claims SET profile=NULL WHERE device_id=$1 AND download_count=3`, id); err != nil {
		return nil, err
	}
	if err = audit(ctx, tx, tenant, "enrollment-browser", "apple.enrollment.download", id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return data, nil
}

func (s *Store) CleanupEnrollmentClaims(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE mdm_apple_enrollment_claims c SET profile=NULL FROM mdm_apple_devices d WHERE d.id=c.device_id AND c.profile IS NOT NULL AND (c.download_expires_at<=now() OR d.status<>'authenticating' OR d.udid IS NOT NULL OR c.download_count>=3)`)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM mdm_apple_enrollment_claims WHERE status_expires_at<=now()`)
	return err
}
