package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/ade"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrADEProfile = errors.New("invalid Automated Device Enrollment profile or transition")

type ADEProfileOptions struct {
	MacAdmin                                                                         *MacAdminOptions
	SiteID                                                                           int
	Platform                                                                         Platform
	Name, Department, SupportEmail, SupportPhone                                     string
	Removable, AwaitConfiguration, AllowDeviceLock, AutoAdvance, IgnoreBackupProfile bool
	SkipSetupItems                                                                   []string
}

type ADEEnrollmentProfile struct {
	MacAdmin                                         *MacAdminOptions
	ID, ServerID, Name, Status, RemoteID, Error      string
	SiteID                                           int
	Platform                                         Platform
	Removable, AwaitConfiguration, DeviceLockAllowed bool
	CreatedAt, UpdatedAt, NextAttemptAt              time.Time
	AttemptedAt                                      *time.Time
}

const adeProfileColumns = `id,server_id,site_id,platform,name,status,COALESCE(remote_id,''),error,removable,await_configuration,device_lock_allowed,created_at,updated_at,next_attempt_at,attempted_at,admin_options`

func scanADEProfile(row scanner) (ADEEnrollmentProfile, error) {
	var p ADEEnrollmentProfile
	var admin []byte
	err := row.Scan(&p.ID, &p.ServerID, &p.SiteID, &p.Platform, &p.Name, &p.Status, &p.RemoteID, &p.Error, &p.Removable, &p.AwaitConfiguration, &p.DeviceLockAllowed, &p.CreatedAt, &p.UpdatedAt, &p.NextAttemptAt, &p.AttemptedAt, &admin)
	if err == nil && len(admin) > 0 {
		err = json.Unmarshal(admin, &p.MacAdmin)
		if err == nil && (p.MacAdmin == nil || p.MacAdmin.Validate() != nil || p.Platform != PlatformMacOS || !p.AwaitConfiguration) {
			err = ErrADEProfile
		}
	}
	return p, notFound(err)
}

func (s *Store) ADEProfiles(ctx context.Context, tenant int, server string) ([]ADEEnrollmentProfile, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+adeProfileColumns+` FROM mdm_apple_ade_profiles WHERE tenant_id=$1 AND server_id=$2 ORDER BY created_at DESC,id LIMIT 256`, tenant, server)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []ADEEnrollmentProfile{}
	for rows.Next() {
		p, err := scanADEProfile(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

func adeEnrollmentPermission(p *access.Store, tenant, site int, actor string, deviceLock bool) func(context.Context, *sql.Tx) error {
	return func(ctx context.Context, tx *sql.Tx) error {
		if err := adePermission(p, tenant, actor)(ctx, tx); err != nil {
			return err
		}
		if err := p.AuthorizeTransaction(ctx, tx, actor, access.EnrollDevices, access.Scope{TenantID: tenant, SiteID: site}); err != nil {
			return err
		}
		if deviceLock {
			return p.AuthorizeTransaction(ctx, tx, actor, access.ManageDeviceSecurity, access.Scope{TenantID: tenant, SiteID: site})
		}
		return nil
	}
}

type adeProfileDefinition struct {
	Options ADEProfileOptions
	Profile ade.EnrollmentProfile
}

func (s *Store) CreateADEProfile(ctx context.Context, tenant int, server string, options ADEProfileOptions, actor string, permissions *access.Store) (string, error) {
	return s.createADEProfile(ctx, tenant, server, options, actor, adeEnrollmentPermission(permissions, tenant, options.SiteID, actor, options.AllowDeviceLock || options.MacAdmin != nil))
}

func (s *Store) createADEProfile(ctx context.Context, tenant int, server string, o ADEProfileOptions, actor string, authorize func(context.Context, *sql.Tx) error) (string, error) {
	if o.SiteID <= 0 || (o.Platform != PlatformMacOS && o.Platform != PlatformIOS && o.Platform != PlatformIPadOS) || o.Platform != PlatformMacOS && (o.AllowDeviceLock || o.AutoAdvance) {
		return "", ErrADEProfile
	}
	if o.MacAdmin != nil && (o.Platform != PlatformMacOS || !o.AwaitConfiguration || o.MacAdmin.Validate() != nil) {
		return "", ErrADEProfile
	}
	o.Name = strings.TrimSpace(o.Name)
	ctx, stop := context.WithTimeout(ctx, 20*time.Second)
	defer stop()
	tx, err := s.adeTx(ctx, tenant, actor, authorize)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var status string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, server).Scan(&status); err != nil {
		return "", notFound(err)
	}
	if status != "connected" {
		return "", ErrADEProfile
	}
	var site, count int
	if err = tx.QueryRowContext(ctx, `SELECT id FROM sites WHERE id=$1 AND tenant_sites=$2 FOR SHARE`, o.SiteID, tenant).Scan(&site); err != nil {
		return "", notFound(err)
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627902,$1::integer)`, tenant); err != nil {
		return "", err
	}
	var publicURL string
	var pushExpiry time.Time
	if err = tx.QueryRowContext(ctx, `SELECT public_url,push_expires_at FROM mdm_apple_settings WHERE tenant_id=$1`, tenant).Scan(&publicURL, &pushExpiry); err != nil {
		return "", notFound(err)
	}
	if !pushExpiry.After(time.Now().Add(time.Minute)) {
		return "", ErrADEProfile
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_ade_profiles WHERE tenant_id=$1 AND server_id=$2`, tenant, server).Scan(&count); err != nil {
		return "", err
	}
	if count >= 256 {
		return "", ErrADEProfile
	}
	selector, err := randomToken()
	if err != nil {
		return "", err
	}
	id := uuid.NewString()
	profile := ade.EnrollmentProfile{Name: o.Name, URL: publicURL + "/mdm/apple/ade/" + selector, Department: o.Department, SupportEmail: o.SupportEmail, SupportPhone: o.SupportPhone, OrganizationMagic: "openuem-" + id, AllowPairing: true, Supervised: true, Mandatory: true, Removable: o.Removable, AwaitDeviceConfigured: o.AwaitConfiguration, AutoAdvance: o.AutoAdvance, IgnoreBackupProfile: o.IgnoreBackupProfile, SkipSetupItems: o.SkipSetupItems}
	if profile.Validate() != nil {
		return "", ErrADEProfile
	}
	plain, err := json.Marshal(adeProfileDefinition{Options: o, Profile: profile})
	if err != nil {
		return "", err
	}
	defer clear(plain)
	sealed, err := s.secrets.seal(plain, secretPurpose(tenant, id, "ade_definition"))
	if err != nil {
		return "", err
	}
	var admin any
	if o.MacAdmin != nil {
		data, e := json.Marshal(o.MacAdmin)
		if e != nil {
			return "", e
		}
		admin = string(data)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_profiles(id,tenant_id,server_id,site_id,platform,name,definition,selector_hash,public_url,removable,await_configuration,device_lock_allowed,admin_options) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, id, tenant, server, o.SiteID, o.Platform, o.Name, sealed, digest([]byte(selector)), publicURL, o.Removable, o.AwaitConfiguration, o.AllowDeviceLock, admin)
	if err != nil {
		return "", err
	}
	if err = audit(ctx, tx, tenant, actor, "apple.ade.profile.create", id); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return id, nil
}

func (s *Store) openADEProfile(ctx context.Context, tx *sql.Tx, tenant int, p ADEEnrollmentProfile) (ade.EnrollmentProfile, error) {
	var sealed []byte
	var origin, selectorHash string
	if err := tx.QueryRowContext(ctx, `SELECT definition,public_url,selector_hash FROM mdm_apple_ade_profiles WHERE tenant_id=$1 AND id=$2`, tenant, p.ID).Scan(&sealed, &origin, &selectorHash); err != nil {
		return ade.EnrollmentProfile{}, err
	}
	plain, err := s.secrets.open(sealed, secretPurpose(tenant, p.ID, "ade_definition"))
	if err != nil {
		return ade.EnrollmentProfile{}, ErrADEProfile
	}
	defer clear(plain)
	var definition adeProfileDefinition
	if json.Unmarshal(plain, &definition) != nil {
		return ade.EnrollmentProfile{}, ErrADEProfile
	}
	o, profile := definition.Options, definition.Profile
	selector := strings.TrimPrefix(profile.URL, origin+"/mdm/apple/ade/")
	if !validEnrollmentToken(selector) || digest([]byte(selector)) != selectorHash || o.SiteID != p.SiteID || o.Platform != p.Platform || o.Name != p.Name || o.Removable != p.Removable || o.AwaitConfiguration != p.AwaitConfiguration || o.AllowDeviceLock != p.DeviceLockAllowed || !reflect.DeepEqual(o.MacAdmin, p.MacAdmin) || profile.Name != p.Name || profile.Removable != p.Removable || profile.AwaitDeviceConfigured != p.AwaitConfiguration || !profile.Supervised || !profile.Mandatory || profile.Validate() != nil {
		return ade.EnrollmentProfile{}, ErrADEProfile
	}
	return profile, nil
}

// openADEEnrollmentService requires a locked server row. It validates the live
// Apple account every time; an encrypted token alone is not authority to enroll.
func (s *Store) openADEEnrollmentService(ctx context.Context, tx *sql.Tx, tenant int, server string) (ade.EnrollmentService, error) {
	var sealed []byte
	var hash, expectedServer, expectedOrg, status string
	var retry *time.Time
	err := tx.QueryRowContext(ctx, `SELECT status,token,token_hash,COALESCE(apple_server_id::text,''),apple_organization_id,retry_after FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&status, &sealed, &hash, &expectedServer, &expectedOrg, &retry)
	if err != nil {
		return nil, notFound(err)
	}
	if status != "connected" {
		return nil, ErrADE
	}
	if retry != nil && retry.After(time.Now()) {
		return nil, &ade.RetryError{After: time.Until(*retry)}
	}
	plain, err := s.secrets.open(sealed, secretPurpose(tenant, server, "ade_token"))
	if err != nil {
		return nil, ade.ErrToken
	}
	defer clear(plain)
	if digest(plain) != hash {
		return nil, ade.ErrToken
	}
	token, err := ade.ParseToken(plain, time.Now())
	if err != nil {
		return nil, err
	}
	defer token.Close()
	if s.adeService == nil {
		return nil, ErrADE
	}
	base := s.adeService(token)
	if base == nil {
		return nil, ErrADE
	}
	client, ok := base.(ade.EnrollmentService)
	if !ok {
		base.Close()
		return nil, ErrADE
	}
	a, err := client.Account(ctx)
	if err == nil && (a.ServerID != expectedServer || a.OrganizationID != expectedOrg) {
		err = ErrADEAccount
	}
	if err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

func adeEnrollmentFailure(cause error) (string, time.Duration) {
	var retry *ade.RetryError
	switch {
	case errors.As(cause, &retry):
		return "throttled", max(time.Second, retry.After)
	case errors.Is(cause, ade.ErrToken):
		return "token_expired", 24 * time.Hour
	case errors.Is(cause, ade.ErrAuthorization):
		return "token_rejected", 24 * time.Hour
	case errors.Is(cause, ErrADEAccount):
		return "account_changed", 24 * time.Hour
	case errors.Is(cause, ErrADEProfile):
		return "profile_invalid", time.Hour
	default:
		return "service_unavailable", 5 * time.Minute
	}
}

func saveADERetry(ctx context.Context, tx *sql.Tx, tenant int, server string, cause error) error {
	var retry *ade.RetryError
	if !errors.As(cause, &retry) {
		return nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_ade_servers SET retry_after=GREATEST(retry_after,$3),next_sync_at=GREATEST(next_sync_at,$3) WHERE tenant_id=$1 AND id=$2`, tenant, server, time.Now().Add(max(time.Second, retry.After)))
	return err
}

func (s *Store) ChangeADEProfile(ctx context.Context, tenant int, server, id, operation, actor string, permissions *access.Store) error {
	return s.changeADEProfile(ctx, tenant, server, id, operation, actor, adePermission(permissions, tenant, actor))
}

// Retrying uncertain publication is an explicit administrator action. A prior
// unassigned remote profile may exist; it never becomes this version's authority
// unless its returned identifier has been committed here.
func (s *Store) changeADEProfile(ctx context.Context, tenant int, server, id, operation, actor string, authorize func(context.Context, *sql.Tx) error) error {
	if operation != "retry" && operation != "disable" {
		return ErrADEProfile
	}
	tx, err := s.adeTx(ctx, tenant, actor, authorize)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var connected string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, server).Scan(&connected); err != nil {
		return notFound(err)
	}
	p, err := scanADEProfile(tx.QueryRowContext(ctx, `SELECT `+adeProfileColumns+` FROM mdm_apple_ade_profiles WHERE tenant_id=$1 AND server_id=$2 AND id=$3 FOR UPDATE`, tenant, server, id))
	if err != nil {
		return err
	}
	if p.Status == "publishing" {
		return ErrADEProfile
	}
	if operation == "retry" {
		if connected != "connected" || p.Status != "unknown" || p.RemoteID != "" {
			return ErrADEProfile
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_profiles SET status='queued',attempt_id=NULL,error='',next_attempt_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1`, id)
	} else {
		var inUse bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_ade_targets WHERE tenant_id=$1 AND server_id=$2 AND profile_id=$3)`, tenant, server, id).Scan(&inUse); err != nil {
			return err
		}
		if inUse {
			return ErrADEProfile
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_profiles SET status='disabled',updated_at=clock_timestamp() WHERE id=$1`, id)
	}
	if err != nil {
		return err
	}
	if err = audit(ctx, tx, tenant, actor, "apple.ade.profile."+operation, id); err != nil {
		return err
	}
	return tx.Commit()
}

// claimADEPublication commits the attempt before a remote mutation can begin.
// A process lost after this commit leaves an uncertain attempt, not a blank retry.
func (s *Store) claimADEPublication(ctx context.Context, tenant int, server, id string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var connection string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2 FOR UPDATE SKIP LOCKED`, tenant, server).Scan(&connection); errors.Is(err, sql.ErrNoRows) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	p, err := scanADEProfile(tx.QueryRowContext(ctx, `SELECT `+adeProfileColumns+` FROM mdm_apple_ade_profiles WHERE tenant_id=$1 AND server_id=$2 AND id=$3 FOR UPDATE`, tenant, server, id))
	if err != nil {
		return "", err
	}
	if p.Status == "publishing" {
		if p.AttemptedAt == nil || time.Since(*p.AttemptedAt) < 2*time.Minute {
			return "", nil
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_profiles SET status='unknown',error='publication_interrupted',updated_at=clock_timestamp() WHERE id=$1`, id); err != nil {
			return "", err
		}
		if err = auditOutcome(ctx, tx, tenant, "system", "apple.ade.profile.publish.uncertain", id, "deferred"); err != nil {
			return "", err
		}
		return "", tx.Commit()
	}
	if connection != "connected" || p.Status != "queued" || p.NextAttemptAt.After(time.Now()) {
		return "", nil
	}
	var ready bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_settings WHERE tenant_id=$1 AND push_expires_at>clock_timestamp()+interval '1 minute')`, tenant).Scan(&ready); err != nil {
		return "", err
	}
	if !ready {
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_profiles SET error='push_expired',next_attempt_at=clock_timestamp()+interval '5 minutes' WHERE id=$1`, id)
		if err != nil {
			return "", err
		}
		return "", tx.Commit()
	}
	attempt := uuid.NewString()
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_profiles SET status='publishing',attempt_id=$2,attempted_at=clock_timestamp(),updated_at=clock_timestamp(),error='' WHERE id=$1`, id, attempt); err != nil {
		return "", err
	}
	if err = audit(ctx, tx, tenant, "system", "apple.ade.profile.publish.start", id); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return attempt, nil
}

func (s *Store) publishADEProfile(ctx context.Context, tenant int, server, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	attempt, err := s.claimADEPublication(ctx, tenant, server, id)
	if err != nil || attempt == "" {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var connection string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, server).Scan(&connection); err != nil {
		return err
	}
	p, err := scanADEProfile(tx.QueryRowContext(ctx, `SELECT `+adeProfileColumns+` FROM mdm_apple_ade_profiles WHERE tenant_id=$1 AND server_id=$2 AND id=$3 AND attempt_id=$4 AND status='publishing' FOR UPDATE`, tenant, server, id, attempt))
	if err != nil {
		return err
	}
	deferFailure := func(cause error) error {
		code, after := adeEnrollmentFailure(cause)
		if err := saveADERetry(ctx, tx, tenant, server, cause); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_ade_profiles SET status='queued',error=$2,next_attempt_at=$3,updated_at=clock_timestamp() WHERE id=$1`, id, code, time.Now().Add(after))
		if err != nil {
			return err
		}
		if err = auditOutcome(ctx, tx, tenant, "system", "apple.ade.profile.preflight", id, "failure"); err != nil {
			return err
		}
		return tx.Commit()
	}
	if connection != "connected" {
		return deferFailure(ErrADE)
	}
	definition, err := s.openADEProfile(ctx, tx, tenant, p)
	if err != nil {
		return deferFailure(err)
	}
	network, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	client, err := s.openADEEnrollmentService(network, tx, tenant, server)
	if err != nil {
		return deferFailure(err)
	}
	defer client.Close()
	remoteID, remoteErr := client.DefineProfile(network, definition)
	stop()
	if remoteErr != nil {
		if err = saveADERetry(ctx, tx, tenant, server, remoteErr); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_profiles SET status='unknown',error='publication_uncertain',updated_at=clock_timestamp() WHERE id=$1`, id); err != nil {
			return err
		}
		if err = auditOutcome(ctx, tx, tenant, "system", "apple.ade.profile.publish.uncertain", id, "deferred"); err != nil {
			return err
		}
	} else {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_profiles SET status='published',remote_id=$2,error='',updated_at=clock_timestamp() WHERE id=$1`, id, remoteID); err != nil {
			return err
		}
		if err = audit(ctx, tx, tenant, "system", "apple.ade.profile.publish", id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
