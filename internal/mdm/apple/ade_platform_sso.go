package apple

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"howett.net/plist"
)

var ErrADEPlatformSSO = errors.New("invalid or unavailable ADE Platform SSO provider binding")

// ProviderConfirmed records an operator's review of the approved app/provider
// relationship. InstalledApplicationList cannot inspect an embedded extension
// or prove that the identity provider supports silent device registration.
type ADEPlatformSSOOptions struct {
	ProfileRevisionID    string `json:"profile_revision_id"`
	ApplicationVersionID string `json:"application_version_id"`
	ProviderConfirmed    bool   `json:"provider_confirmed"`
	ApprovalReason       string `json:"approval_reason"`
}

func validateADEPlatformSSOOptions(o ADEProfileOptions) error {
	if o.PlatformSSO == nil {
		return nil
	}
	r := o.PlatformSSO
	if o.Platform != PlatformMacOS || !o.AutoAdvance || !o.AwaitConfiguration || o.MacAdmin == nil || o.MacAdmin.Validate() != nil || o.MacAdmin.PrimaryAccount != "skip" || !r.ProviderConfirmed || !profileRevisionUUID(r.ProfileRevisionID) || !profileRevisionUUID(r.ApplicationVersionID) || !slices.Contains(o.RequiredApplications, r.ApplicationVersionID) || !validMacAppText(r.ApprovalReason, 1000) || strings.TrimSpace(r.ApprovalReason) != r.ApprovalReason {
		return ErrADEPlatformSSO
	}
	return nil
}

func validateADEPlatformSSOProfile(p *Profile) error {
	if p == nil || p.Scope != "System" || validatePlatformSSOProfile(p, nil) != nil {
		return ErrADEPlatformSSO
	}
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		return ErrADEPlatformSSO
	}
	items, _ := root["PayloadContent"].([]any)
	count := 0
	for _, value := range items {
		item, _ := value.(map[string]any)
		if stringValue(item, "PayloadType") != "com.apple.extensiblesso" {
			continue
		}
		count++
		configuration, ok := item["PlatformSSO"].(map[string]any)
		if !ok || configuration["EnableRegistrationDuringSetup"] != true || configuration["EnableCreateFirstUserDuringSetup"] != false || configuration["UseSharedDeviceKeys"] != true || configuration["EnableCreateUserAtLogin"] != true {
			return ErrADEPlatformSSO
		}
	}
	// One chosen host app is reviewed against one extension in this prerequisite.
	// Other ordinary SSO profiles are not prohibited by this binding.
	if count != 1 {
		return ErrADEPlatformSSO
	}
	return nil
}

func (s *Store) availableADEPlatformSSO(ctx context.Context, tx *sql.Tx, tenant int, o *ADEPlatformSSOOptions, lockCatalog bool) (*Profile, error) {
	if o == nil {
		return nil, nil
	}
	p, err := s.profileRevisionPayload(ctx, tx, tenant, o.ProfileRevisionID)
	if err != nil {
		return nil, err
	}
	if err = validateADEPlatformSSOProfile(p); err != nil {
		return nil, err
	}
	var id string
	if lockCatalog {
		err = tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_profiles WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, p.ID).Scan(&id)
	} else {
		err = tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_profiles WHERE tenant_id=$1 AND id=$2`, tenant, p.ID).Scan(&id)
	}
	if err != nil {
		return nil, notFound(err)
	}
	return p, nil
}

func (s *Store) saveADEPlatformSSOBinding(ctx context.Context, tx *sql.Tx, tenant int, server, id string, o *ADEPlatformSSOOptions, p *Profile, actor string) error {
	if o == nil {
		return nil
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_profile_sso(tenant_id,server_id,ade_profile_id,profile_id,profile_revision_id,package_id,application_version_id,approval_reason,approved_by) SELECT $1,$2,$3,$4,$5,package_id,version_id,$7,$8 FROM mdm_apple_ade_profile_apps WHERE tenant_id=$1 AND profile_id=$3 AND version_id=$6`, tenant, server, id, p.ID, o.ProfileRevisionID, o.ApplicationVersionID, o.ApprovalReason, actor)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return ErrADEPlatformSSO
	}
	return err
}

func (s *Store) admitADEPlatformSSO(ctx context.Context, tx *sql.Tx, tenant int, device string, p ADEEnrollmentProfile) error {
	if p.PlatformSSO == nil {
		return nil
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_device_sso(id,tenant_id,device_id,ade_profile_id,profile_id,profile_revision_id,package_id,application_version_id,current_revision_id) SELECT $1,tenant_id,$2,ade_profile_id,profile_id,profile_revision_id,package_id,application_version_id,$1 FROM mdm_apple_ade_profile_sso WHERE tenant_id=$3 AND ade_profile_id=$4`, uuid.NewString(), device, tenant, p.ID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return ErrADEPlatformSSO
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_sso_revisions(id,tenant_id,device_id,requirement_id,profile_id,package_id,profile_revision_id,application_version_id,actor,reason,created_at) SELECT r.id,r.tenant_id,r.device_id,r.id,r.profile_id,r.package_id,r.profile_revision_id,r.application_version_id,p.approved_by,p.approval_reason,r.created_at FROM mdm_apple_ade_device_sso r JOIN mdm_apple_ade_profile_sso p ON p.tenant_id=r.tenant_id AND p.ade_profile_id=r.ade_profile_id WHERE r.tenant_id=$1 AND r.device_id=$2`, tenant, device)
	return err
}

func activeADEProfileRequirement(ctx context.Context, tx *sql.Tx, tenant int, device, profile string) (string, string, error) {
	var id, revision string
	err := tx.QueryRowContext(ctx, `SELECT r.id,b.profile_revision_id FROM mdm_apple_ade_device_sso r JOIN mdm_apple_ade_sso_revisions b ON b.id=r.current_revision_id JOIN mdm_apple_ade_admissions a ON a.tenant_id=r.tenant_id AND a.device_id=r.device_id WHERE r.tenant_id=$1 AND r.device_id=$2 AND r.profile_id=$3 AND a.setup_state<>'complete'`, tenant, device, profile).Scan(&id, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	return id, revision, err
}

func guardADEProviderApplication(ctx context.Context, tx *sql.Tx, d *Device, v SoftwareVersion, operation string) error {
	var expected string
	err := tx.QueryRowContext(ctx, `SELECT b.application_version_id FROM mdm_apple_ade_device_sso r JOIN mdm_apple_ade_sso_revisions b ON b.id=r.current_revision_id JOIN mdm_apple_ade_admissions a ON a.tenant_id=r.tenant_id AND a.device_id=r.device_id WHERE r.tenant_id=$1 AND r.device_id=$2 AND r.package_id=$3 AND a.setup_state<>'complete'`, d.TenantID, d.ID, v.PackageID).Scan(&expected)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err == nil && (operation != "install" || expected != v.ID) {
		return ErrADEPlatformSSO
	}
	return err
}

func (s *Store) RepairADEPlatformSSO(ctx context.Context, scope Scope, device, expected, reason, actor string, permissions *access.Store) error {
	if permissions == nil {
		return access.ErrDenied
	}
	return s.repairADEPlatformSSO(ctx, scope, device, expected, reason, actor, func(ctx context.Context, tx *sql.Tx) error {
		if err := adeEnrollmentPermission(permissions, scope.TenantID, scope.SiteID, actor, false)(ctx, tx); err != nil {
			return err
		}
		return permissions.AuthorizeTransaction(ctx, tx, actor, access.AssignProfiles, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID})
	})
}

func (s *Store) repairADEPlatformSSO(ctx context.Context, scope Scope, device, expected, reason, actor string, authorize func(context.Context, *sql.Tx) error) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if !profileRevisionUUID(expected) || !validMacAppText(reason, 1000) || actor == "" {
		return ErrADEPlatformSSO
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if authorize != nil {
		if err = authorize(ctx, tx); err != nil {
			return err
		}
	}
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE tenant_id=$1 AND id=$2 AND ($3=0 OR site_id=$3) FOR UPDATE`, scope.TenantID, device, scope.SiteID))
	if err != nil {
		return err
	}
	var requirement, revision, binding, release string
	var eligible bool
	err = tx.QueryRowContext(ctx, `SELECT r.id,b.profile_revision_id,b.id,COALESCE(a.setup_command_id::text,''),COALESCE(a.awaiting_configuration AND a.setup_state IN ('awaiting','releasing') AND NOT EXISTS(SELECT 1 FROM mdm_apple_commands c WHERE c.tenant_id=a.tenant_id AND c.device_id=a.device_id AND c.ade_setup AND c.attempts>0),false) FROM mdm_apple_ade_device_sso r JOIN mdm_apple_ade_sso_revisions b ON b.id=r.current_revision_id JOIN mdm_apple_ade_admissions a ON a.tenant_id=r.tenant_id AND a.device_id=r.device_id WHERE r.tenant_id=$1 AND r.device_id=$2`, scope.TenantID, device).Scan(&requirement, &revision, &binding, &release, &eligible)
	if err != nil {
		return notFound(err)
	}
	if !eligible || expected != binding || d.Status != "enrolled" {
		return ErrConflict
	}
	p, err := s.profileRevisionPayload(ctx, tx, scope.TenantID, revision)
	if err != nil {
		return err
	}
	if err = s.assignWithADERequirement(ctx, tx, d, p, "installed", requirement); err != nil {
		return err
	}
	if release != "" {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='cancelled',payload='\x',completed_at=clock_timestamp() WHERE id=$1 AND attempts=0`, release); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_admissions SET setup_state='awaiting',setup_command_id=NULL,setup_error='platform_sso_pending',setup_verify_after=clock_timestamp(),setup_updated_at=clock_timestamp(),next_setup_at=clock_timestamp() WHERE device_id=$1`, device); err != nil {
		return err
	}
	if _, err = s.enqueue(ctx, tx, d, "DeviceInformation", map[string]any{"Queries": inventoryQueriesFor(*d)}, nil, nil); err != nil {
		return err
	}
	// Keep the operator's reason in its own retained receipt, not in a command
	// payload or an unstructured audit message that might expose profile secrets.
	id := uuid.NewString()
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_sso_repairs(id,tenant_id,device_id,requirement_id,profile_revision_id,actor,reason,binding_revision_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, scope.TenantID, device, requirement, revision, actor, reason, binding); err != nil {
		return err
	}
	if err = audit(ctx, tx, scope.TenantID, actor, "apple.ade.platform_sso.repair", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) reconcileADEPlatformSSO(ctx context.Context, tx *sql.Tx, d *Device) (bool, error) {
	var requirement, revision, application string
	var created time.Time
	err := tx.QueryRowContext(ctx, `SELECT r.id,b.profile_revision_id,b.application_version_id,b.created_at FROM mdm_apple_ade_device_sso r JOIN mdm_apple_ade_sso_revisions b ON b.id=r.current_revision_id WHERE r.tenant_id=$1 AND r.device_id=$2`, d.TenantID, d.ID).Scan(&requirement, &revision, &application, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	p, err := s.profileRevisionPayload(ctx, tx, d.TenantID, revision)
	if err != nil {
		return false, err
	}
	state := "profile_pending"
	var desired, status string
	var assigned int
	err = tx.QueryRowContext(ctx, `SELECT revision,desired,status FROM mdm_apple_profile_assignments WHERE tenant_id=$1 AND device_id=$2 AND profile_id=$3`, d.TenantID, d.ID, p.ID).Scan(&assigned, &desired, &status)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if err == nil {
		if assigned != p.Revision || desired != "installed" {
			state = "profile_revision_mismatch"
		} else if status == "verified" {
			var fresh bool
			if err = tx.QueryRowContext(ctx, `SELECT COALESCE(profiles_query_at>=$2 AND profiles_at>=clock_timestamp()-interval '24 hours' AND profiles_at<=clock_timestamp(),false) FROM mdm_apple_devices WHERE id=$1`, d.ID, created).Scan(&fresh); err != nil {
				return false, err
			}
			if fresh {
				state = ""
			}
		} else if status == "failed" || status == "missing" || status == "not_managed" {
			state = "profile_attention_required"
		}
	} else {
		if _, err = tx.ExecContext(ctx, `SAVEPOINT ade_sso_assignment`); err != nil {
			return false, err
		}
		if err = s.assignWithADERequirement(ctx, tx, d, p, "installed", requirement); err != nil {
			cause := err
			if _, rollbackErr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT ade_sso_assignment`); rollbackErr != nil {
				return false, rollbackErr
			}
			if !errors.Is(cause, ErrProfilePrerequisite) && !errors.Is(cause, ErrADEPlatformSSO) {
				return false, cause
			}
			state = "profile_prerequisites_required"
		}
		if _, err = tx.ExecContext(ctx, `RELEASE SAVEPOINT ade_sso_assignment`); err != nil {
			return false, err
		}
	}
	var bound bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_ade_device_apps WHERE tenant_id=$1 AND device_id=$2 AND version_id=$3)`, d.TenantID, d.ID, application).Scan(&bound); err != nil {
		return false, err
	}
	if !bound {
		state = "provider_application_mismatch"
	}
	result, err := tx.ExecContext(ctx, `UPDATE mdm_apple_ade_device_sso SET error=$2,updated_at=clock_timestamp() WHERE id=$1 AND error<>$2`, requirement, state)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err == nil && n > 0 {
		action := state
		if action == "" {
			action = "ready"
		}
		err = audit(ctx, tx, d.TenantID, "enrollment-service", "apple.ade.platform_sso."+action, requirement)
	}
	return state == "", err
}
