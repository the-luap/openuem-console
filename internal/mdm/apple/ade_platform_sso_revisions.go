package apple

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type ADEPlatformSSOCorrection struct {
	ExpectedRevisionID, ProfileRevisionID, ApplicationVersionID, Reason string
	ProviderConfirmed                                                   bool
}

type ADEPlatformSSORevision struct {
	ID, PreviousID, ProfileRevisionID, ProfileName, ApplicationVersionID, ApplicationName, ApplicationVersion, Actor, Reason string
	ProfileRevision                                                                                                          int
	CreatedAt                                                                                                                time.Time
}

func (s *Store) CorrectADEPlatformSSO(ctx context.Context, scope Scope, device string, o ADEPlatformSSOCorrection, actor string, permissions *access.Store) error {
	if permissions == nil {
		return access.ErrDenied
	}
	return s.correctADEPlatformSSO(ctx, scope, device, o, actor, func(ctx context.Context, tx *sql.Tx) error {
		if err := adeEnrollmentPermission(permissions, scope.TenantID, scope.SiteID, actor, false, true)(ctx, tx); err != nil {
			return err
		}
		return permissions.AuthorizeTransaction(ctx, tx, actor, access.AssignProfiles, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID})
	})
}

func (s *Store) correctADEPlatformSSO(ctx context.Context, scope Scope, device string, o ADEPlatformSSOCorrection, actor string, authorize func(context.Context, *sql.Tx) error) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	o.Reason = strings.TrimSpace(o.Reason)
	if !profileRevisionUUID(o.ExpectedRevisionID) || !profileRevisionUUID(o.ProfileRevisionID) || !profileRevisionUUID(o.ApplicationVersionID) || !o.ProviderConfirmed || !validMacAppText(o.Reason, 1000) || actor == "" {
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
	d, err := s.lockMacAppDevice(ctx, tx, scope, device)
	if err != nil {
		return err
	}
	var requirement, current, profile, packageID, oldProfile, oldApp, appRequirement, release string
	var eligible bool
	err = tx.QueryRowContext(ctx, `SELECT r.id,r.current_revision_id,r.profile_id,r.package_id,b.profile_revision_id,b.application_version_id,apps.id,COALESCE(a.setup_command_id::text,''),COALESCE(a.awaiting_configuration AND a.setup_state IN ('awaiting','releasing') AND NOT EXISTS(SELECT 1 FROM mdm_apple_commands c WHERE c.tenant_id=a.tenant_id AND c.device_id=a.device_id AND c.ade_setup AND c.attempts>0),false)
 FROM mdm_apple_ade_device_sso r JOIN mdm_apple_ade_sso_revisions b ON b.id=r.current_revision_id
 JOIN mdm_apple_ade_admissions a ON a.tenant_id=r.tenant_id AND a.device_id=r.device_id
 JOIN mdm_apple_ade_device_apps apps ON apps.tenant_id=r.tenant_id AND apps.device_id=r.device_id AND apps.package_id=r.package_id AND apps.version_id=b.application_version_id
 WHERE r.tenant_id=$1 AND r.device_id=$2 FOR UPDATE OF r,a`, scope.TenantID, device).Scan(&requirement, &current, &profile, &packageID, &oldProfile, &oldApp, &appRequirement, &release, &eligible)
	if err != nil {
		return notFound(err)
	}
	if !eligible || current != o.ExpectedRevisionID || oldProfile == o.ProfileRevisionID && oldApp == o.ApplicationVersionID {
		return ErrConflict
	}
	p, err := s.availableADEPlatformSSO(ctx, tx, scope.TenantID, &ADEPlatformSSOOptions{ProfileRevisionID: o.ProfileRevisionID}, false)
	if err != nil {
		return err
	}
	if p.ID != profile {
		return ErrADEPlatformSSO
	}
	if err = validatePlatformSSOProfile(p, d); err != nil {
		return ErrADEPlatformSSO
	}
	versions, err := s.approvedADEApplications(ctx, tx, scope.TenantID, []string{o.ApplicationVersionID})
	if err != nil {
		return err
	}
	if len(versions) != 1 || versions[0].PackageID != packageID || !macAppCompatible(*d, versions[0]) {
		return ErrADEPlatformSSO
	}
	change := uuid.NewString()
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_sso_revisions(id,tenant_id,device_id,requirement_id,profile_id,package_id,profile_revision_id,application_version_id,previous_id,actor,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, change, scope.TenantID, device, requirement, profile, packageID, o.ProfileRevisionID, o.ApplicationVersionID, current, actor, o.Reason); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_device_sso SET current_revision_id=$2,error='profile_pending',updated_at=clock_timestamp() WHERE id=$1`, requirement, change); err != nil {
		return err
	}
	// Publish the pair inside this transaction before the shared app/profile
	// ownership checks. Any incompatible or unresolved operation rolls it back.
	if err = s.assignWithADERequirement(ctx, tx, d, p, "installed", requirement); err != nil {
		return err
	}
	if oldApp != o.ApplicationVersionID {
		if err = s.replaceADEApplicationTx(ctx, tx, d, appRequirement, o.ApplicationVersionID, o.Reason, actor, false); err != nil {
			return err
		}
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
	if err = audit(ctx, tx, scope.TenantID, actor, "apple.ade.platform_sso.correct", change); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ADEPlatformSSORevisions(ctx context.Context, scope Scope, device, before string) (*ADEPlatformSSOStatus, []ADEPlatformSSORevision, string, error) {
	r, err := s.ADEPlatformSSOStatus(ctx, scope, device)
	if err != nil {
		return nil, nil, "", err
	}
	if r == nil {
		return nil, nil, "", ErrNotFound
	}
	var stamp, cursor any
	if before != "" {
		if !profileRevisionUUID(before) {
			return nil, nil, "", ErrADEPlatformSSO
		}
		var at time.Time
		if err = s.db.QueryRowContext(ctx, `SELECT created_at FROM mdm_apple_ade_sso_revisions WHERE tenant_id=$1 AND device_id=$2 AND requirement_id=$3 AND id=$4`, scope.TenantID, device, r.ID, before).Scan(&at); err != nil {
			return nil, nil, "", notFound(err)
		}
		stamp, cursor = at, before
	}
	rows, err := s.db.QueryContext(ctx, `SELECT b.id,COALESCE(b.previous_id::text,''),b.profile_revision_id,p.name,p.revision,b.application_version_id,v.name,v.version,b.actor,b.reason,b.created_at FROM mdm_apple_ade_sso_revisions b JOIN mdm_apple_devices d ON d.id=b.device_id AND d.tenant_id=b.tenant_id JOIN mdm_apple_profile_revisions p ON p.id=b.profile_revision_id AND p.tenant_id=b.tenant_id JOIN uem_software_versions v ON v.id=b.application_version_id AND v.tenant_id=b.tenant_id WHERE b.tenant_id=$1 AND b.device_id=$2 AND b.requirement_id=$3 AND ($4::timestamptz IS NULL OR (b.created_at,b.id)<($4,$5::uuid)) AND ($6=0 OR d.site_id=$6) ORDER BY b.created_at DESC,b.id DESC LIMIT 101`, scope.TenantID, device, r.ID, stamp, cursor, scope.SiteID)
	if err != nil {
		return nil, nil, "", err
	}
	defer rows.Close()
	items := []ADEPlatformSSORevision{}
	for rows.Next() {
		var item ADEPlatformSSORevision
		if err = rows.Scan(&item.ID, &item.PreviousID, &item.ProfileRevisionID, &item.ProfileName, &item.ProfileRevision, &item.ApplicationVersionID, &item.ApplicationName, &item.ApplicationVersion, &item.Actor, &item.Reason, &item.CreatedAt); err != nil {
			return nil, nil, "", err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, nil, "", err
	}
	next := ""
	if len(items) > 100 {
		items = items[:100]
		next = items[99].ID
	}
	return r, items, next, nil
}
