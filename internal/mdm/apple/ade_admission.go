package apple

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/ade"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

func sameADEDefinition(a, b ade.EnrollmentProfile) bool {
	a.SkipSetupItems = append([]string(nil), a.SkipSetupItems...)
	b.SkipSetupItems = append([]string(nil), b.SkipSetupItems...)
	sort.Strings(a.SkipSetupItems)
	sort.Strings(b.SkipSetupItems)
	x, e1 := json.Marshal(a)
	y, e2 := json.Marshal(b)
	defer clear(x)
	defer clear(y)
	return e1 == nil && e2 == nil && bytes.Equal(x, y)
}

// admitADE accepts an already verified device statement. Only the public HTTP
// boundary performs production signature verification; this helper never trusts
// an invitation selector or an inventory row in place of that verification.
func (s *Store) admitADE(ctx context.Context, selector string, info *ade.MachineInfo) ([]byte, error) {
	if !validEnrollmentToken(selector) || info == nil || !ade.ValidSerial(info.Serial) || len(info.UDID) == 0 || len(info.UDID) > 64 || len(info.SignerFingerprint) != 64 {
		return nil, ErrUnauthorized
	}
	if _, err := hex.DecodeString(info.SignerFingerprint); err != nil {
		return nil, ErrUnauthorized
	}
	platform := DetectPlatform(info.Product)
	if platform == PlatformUnknown {
		return nil, ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	var tenant int
	var server, id string
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id,server_id,id FROM mdm_apple_ade_profiles WHERE selector_hash=$1 AND status='published'`, digest([]byte(selector))).Scan(&tenant, &server, &id)
	if err != nil {
		return nil, notFound(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var connected string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, server).Scan(&connected); err != nil {
		return nil, err
	}
	if connected != "connected" {
		return nil, ErrUnauthorized
	}
	p, err := scanADEProfile(tx.QueryRowContext(ctx, `SELECT `+adeProfileColumns+` FROM mdm_apple_ade_profiles WHERE tenant_id=$1 AND id=$2 AND selector_hash=$3 AND status='published' FOR SHARE`, tenant, id, digest([]byte(selector))))
	if err != nil {
		return nil, err
	}
	if p.Platform != platform {
		return nil, ErrUnauthorized
	}
	definition, err := s.openADEProfile(ctx, tx, tenant, p)
	if err != nil {
		return nil, err
	}
	var generation int64
	var wanted string
	if err = tx.QueryRowContext(ctx, `SELECT generation,COALESCE(profile_id::text,'') FROM mdm_apple_ade_targets WHERE tenant_id=$1 AND server_id=$2 AND serial=$3 FOR UPDATE`, tenant, server, info.Serial).Scan(&generation, &wanted); err != nil {
		return nil, notFound(err)
	}
	if wanted != id {
		return nil, ErrUnauthorized
	}
	var deviceID, expectedUDID, fingerprint, existingProfile, state string
	var expires time.Time
	var retryProfile []byte
	err = tx.QueryRowContext(ctx, `SELECT a.device_id,a.expected_udid,a.signer_fingerprint,a.profile_id,a.expires_at,a.retry_profile,d.status FROM mdm_apple_ade_admissions a JOIN mdm_apple_devices d ON d.id=a.device_id AND d.tenant_id=a.tenant_id WHERE a.tenant_id=$1 AND a.server_id=$2 AND a.serial=$3 AND a.generation=$4`, tenant, server, info.Serial, generation).Scan(&deviceID, &expectedUDID, &fingerprint, &existingProfile, &expires, &retryProfile, &state)
	retry := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if retry && (expectedUDID != info.UDID || fingerprint != info.SignerFingerprint || existingProfile != id || state != "authenticating" || !expires.After(time.Now()) || len(retryProfile) == 0) {
		return nil, ErrUnauthorized
	}
	if !retry && !info.SignedAt.IsZero() && (info.SignedAt.Before(time.Now().Add(-time.Hour)) || info.SignedAt.After(time.Now().Add(5*time.Minute))) {
		return nil, ErrUnauthorized
	}
	network, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	deferred := func(cause error) ([]byte, error) {
		if err := saveADERetry(ctx, tx, tenant, server, cause); err != nil {
			return nil, err
		}
		if err := auditOutcome(ctx, tx, tenant, "enrollment-service", "apple.ade.profile.admission", id, "deferred"); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, cause
	}
	client, err := s.openADEEnrollmentService(network, tx, tenant, server)
	if err != nil {
		return deferred(err)
	}
	defer client.Close()
	details, err := client.DeviceDetails(network, []string{info.Serial})
	if err != nil {
		return deferred(err)
	}
	detail, found := details[info.Serial]
	if !found || detail.ResponseStatus != "SUCCESS" || detail.ProfileID != p.RemoteID || (detail.ProfileStatus != "assigned" && detail.ProfileStatus != "pushed") {
		return nil, ErrUnauthorized
	}
	remote, err := client.Profile(network, p.RemoteID)
	if err != nil {
		return deferred(err)
	}
	stop()
	if !sameADEDefinition(definition, remote) {
		return nil, ErrUnauthorized
	}
	if retry {
		if !expires.After(time.Now()) {
			return nil, ErrUnauthorized
		}
		plain, err := s.secrets.open(retryProfile, secretPurpose(tenant, deviceID, "ade_retry"))
		if err != nil {
			return nil, err
		}
		if err = audit(ctx, tx, tenant, "device:"+deviceID, "apple.enrollment.ade.retry", deviceID); err != nil {
			clear(plain)
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			clear(plain)
			return nil, err
		}
		return plain, nil
	}
	// No old device row is locked after this settings lock. A prior active
	// enrollment must be revoked explicitly before re-arming its ADE target.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627902,$1::integer)`, tenant); err != nil {
		return nil, err
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_devices WHERE tenant_id=$1 AND status IN ('authenticating','enrolled') AND (udid=$2 OR (enrollment_method='automated_device' AND serial_number=$3)))`, tenant, info.UDID, info.Serial).Scan(&active); err != nil {
		return nil, err
	}
	if active {
		return nil, ErrConflict
	}
	c := &Settings{TenantID: tenant}
	if err = tx.QueryRowContext(ctx, `SELECT public_url,organization,topic,push_expires_at,ca_certificate,ca_key FROM mdm_apple_settings WHERE tenant_id=$1`, tenant).Scan(&c.PublicURL, &c.Organization, &c.Topic, &c.PushExpiresAt, &c.CACertificate, &c.CAKey); err != nil {
		return nil, err
	}
	if !c.PushExpiresAt.After(time.Now().Add(time.Minute)) || !strings.HasPrefix(definition.URL, c.PublicURL+"/mdm/apple/ade/") {
		return nil, ErrADEProfile
	}
	c.CAKey, err = s.secrets.open(c.CAKey, secretPurpose(tenant, "settings", "ca_key"))
	if err != nil {
		return nil, err
	}
	defer clear(c.CAKey)
	var site int
	if err = tx.QueryRowContext(ctx, `SELECT id FROM sites WHERE id=$1 AND tenant_sites=$2 FOR SHARE`, p.SiteID, tenant).Scan(&site); err != nil {
		return nil, notFound(err)
	}
	deviceID = uuid.NewString()
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_devices(id,tenant_id,site_id,name,serial_number,model,os_version,build_version,status,invite_expires_at,certificate_expires_at,enrollment_method,enrollment_platform,device_lock_allowed,removal_disallowed) VALUES($1,$2,$3,$4,$4,$5,$6,$7,'authenticating',clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 year','automated_device',$8,$9,$10)`, deviceID, tenant, site, info.Serial, info.Product, info.OSVersion, info.Build, platform, p.DeviceLockAllowed, !p.Removable)
	if err != nil {
		return nil, err
	}
	profile, err := s.prepareSCEPEnrollment(ctx, tx, c, deviceID)
	if err != nil {
		return nil, err
	}
	if !c.PushExpiresAt.After(time.Now()) {
		clear(profile)
		return nil, ErrADEProfile
	}
	sealed, err := s.secrets.seal(profile, secretPurpose(tenant, deviceID, "ade_retry"))
	if err != nil {
		clear(profile)
		return nil, err
	}
	setup := "pending"
	if !p.AwaitConfiguration {
		setup = "not_requested"
	}
	var signedAt *time.Time
	if !info.SignedAt.IsZero() {
		signedAt = &info.SignedAt
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_admissions(device_id,tenant_id,server_id,serial,generation,profile_id,expected_udid,signer_fingerprint,signed_at,expires_at,retry_profile,setup_state) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,expires_at,$10,$11 FROM mdm_apple_scep_enrollments WHERE device_id=$1`, deviceID, tenant, server, info.Serial, generation, id, info.UDID, info.SignerFingerprint, signedAt, sealed, setup)
	if err != nil {
		clear(profile)
		return nil, err
	}
	for _, version := range p.RequiredApplications {
		if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_device_apps(id,tenant_id,device_id,profile_id,package_id,original_version_id,version_id) SELECT $1,tenant_id,$2,profile_id,package_id,version_id,version_id FROM mdm_apple_ade_profile_apps WHERE tenant_id=$3 AND profile_id=$4 AND version_id=$5`, uuid.NewString(), deviceID, tenant, p.ID, version); err != nil {
			clear(profile)
			return nil, err
		}
	}
	if p.MacAdmin != nil {
		if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_mac_admin_accounts(device_id,tenant_id,options) SELECT $1,tenant_id,admin_options FROM mdm_apple_ade_profiles WHERE id=$2 AND tenant_id=$3`, deviceID, p.ID, tenant); err != nil {
			clear(profile)
			return nil, err
		}
	}
	if err = audit(ctx, tx, tenant, "enrollment-service", "apple.enrollment.ade.admit", deviceID); err != nil {
		clear(profile)
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		clear(profile)
		return nil, err
	}
	return profile, nil
}

// An initial Authenticate must match the signed admission while it is still
// armed. Subsequent inventory cannot replace its serial/UDID; a later Apple
// assignment change does not revoke an already authenticated MDM identity.
func (s *Store) validateADEIdentity(ctx context.Context, tx *sql.Tx, d *Device, udid, serial string) error {
	if d.EnrollmentMethod != "automated_device" {
		return nil
	}
	var expectedUDID, expectedSerial string
	var armed bool
	err := tx.QueryRowContext(ctx, `SELECT a.expected_udid,a.serial,COALESCE((a.expires_at>clock_timestamp() AND t.generation=a.generation AND t.profile_id=a.profile_id AND p.status='published' AND s.status='connected'),false)
 FROM mdm_apple_ade_admissions a JOIN mdm_apple_ade_targets t ON t.tenant_id=a.tenant_id AND t.server_id=a.server_id AND t.serial=a.serial
 JOIN mdm_apple_ade_profiles p ON p.tenant_id=a.tenant_id AND p.id=a.profile_id JOIN mdm_apple_ade_servers s ON s.tenant_id=a.tenant_id AND s.id=a.server_id
 WHERE a.tenant_id=$1 AND a.device_id=$2`, d.TenantID, d.ID).Scan(&expectedUDID, &expectedSerial, &armed)
	if err != nil {
		return ErrUnauthorized
	}
	if udid != expectedUDID || serial != "" && serial != expectedSerial || d.UDID == "" && (!armed || serial == "") {
		return ErrUnauthorized
	}
	return nil
}

func (s *Store) handleADEAdmission(w http.ResponseWriter, r *http.Request, selector string, limits *enrollmentLimiter, identity clientidentity.Policy, logger *slog.Logger) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.TLS == nil || !r.TLS.HandshakeComplete {
		http.Error(w, "secure enrollment transport required", 400)
		return
	}
	if !validEnrollmentToken(selector) || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", 405)
		return
	}
	if !limits.allow(r, identity) {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "retry automated enrollment later", 429)
		return
	}
	select {
	case limits.claims <- struct{}{}:
		defer func() { <-limits.claims }()
	default:
		w.Header().Set("Retry-After", "5")
		http.Error(w, "retry automated enrollment later", 429)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, ade.MaxMachineInfo))
	if err != nil {
		http.Error(w, "invalid automated enrollment request", 413)
		return
	}
	defer clear(body)
	if s.verifyADEMachineInfo == nil {
		http.Error(w, "automated enrollment unavailable", 503)
		return
	}
	info, err := s.verifyADEMachineInfo(body)
	if err != nil {
		http.Error(w, "signed Apple device information required", 403)
		return
	}
	profile, err := s.admitADE(r.Context(), selector, info)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) {
			http.Error(w, "automated enrollment is not authorized for this device", 403)
			return
		}
		logger.Error("Apple automated enrollment admission failed")
		w.Header().Set("Retry-After", "60")
		http.Error(w, "automated enrollment is temporarily unavailable", 503)
		return
	}
	defer clear(profile)
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="openuem-automated-enrollment.mobileconfig"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(profile)
}
