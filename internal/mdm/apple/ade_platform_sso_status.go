package apple

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type ADEPlatformSSOStatus struct {
	ID, ProfileID, ProfileRevisionID, ProfileName, ProfileIdentifier string
	ProfileRevision                                                  int
	ApplicationVersionID, ApplicationName, ApplicationVersion        string
	ApprovedBy, ApprovalReason, Error                                string
	CreatedAt, UpdatedAt                                             time.Time
	ProfileObservedAt                                                *time.Time
	ProfileVerified, CanRepair                                       bool
}

type ADEPlatformSSORepair struct {
	ID, ProfileRevisionID, Actor, Reason string
	CreatedAt                            time.Time
}

// Setup status includes retained revision metadata, never decrypted provider data.
func (s *Store) ADEPlatformSSOStatus(ctx context.Context, scope Scope, device string) (*ADEPlatformSSOStatus, error) {
	if _, err := s.Device(ctx, scope, device); err != nil {
		return nil, err
	}
	var r ADEPlatformSSOStatus
	err := s.db.QueryRowContext(ctx, `SELECT r.id,r.profile_id,r.profile_revision_id,p.name,p.identifier,p.revision,r.application_version_id,v.name,v.version,b.approved_by,b.approval_reason,r.error,r.created_at,r.updated_at,d.profiles_at,
 COALESCE(a.revision=p.revision AND a.desired='installed' AND a.status='verified' AND d.profiles_query_at>=r.created_at AND d.profiles_at>=clock_timestamp()-interval '24 hours' AND d.profiles_at<=clock_timestamp(),false),
 COALESCE(d.status='enrolled' AND e.awaiting_configuration AND e.setup_state IN ('awaiting','releasing') AND COALESCE(c.attempts,0)=0,false)
 FROM mdm_apple_ade_device_sso r JOIN mdm_apple_devices d ON d.id=r.device_id AND d.tenant_id=r.tenant_id
 JOIN mdm_apple_profile_revisions p ON p.id=r.profile_revision_id AND p.tenant_id=r.tenant_id
 JOIN uem_software_versions v ON v.id=r.application_version_id AND v.tenant_id=r.tenant_id
 JOIN mdm_apple_ade_profile_sso b ON b.ade_profile_id=r.ade_profile_id AND b.tenant_id=r.tenant_id
 JOIN mdm_apple_ade_admissions e ON e.device_id=r.device_id AND e.tenant_id=r.tenant_id
 LEFT JOIN mdm_apple_profile_assignments a ON a.device_id=r.device_id AND a.tenant_id=r.tenant_id AND a.profile_id=r.profile_id
 LEFT JOIN mdm_apple_commands c ON c.id=e.setup_command_id
 WHERE r.tenant_id=$1 AND r.device_id=$2 AND ($3=0 OR d.site_id=$3)`, scope.TenantID, device, scope.SiteID).Scan(&r.ID, &r.ProfileID, &r.ProfileRevisionID, &r.ProfileName, &r.ProfileIdentifier, &r.ProfileRevision, &r.ApplicationVersionID, &r.ApplicationName, &r.ApplicationVersion, &r.ApprovedBy, &r.ApprovalReason, &r.Error, &r.CreatedAt, &r.UpdatedAt, &r.ProfileObservedAt, &r.ProfileVerified, &r.CanRepair)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

func (s *Store) ADEPlatformSSORepairs(ctx context.Context, scope Scope, device, before string) (*ADEPlatformSSOStatus, []ADEPlatformSSORepair, string, error) {
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
		if err = s.db.QueryRowContext(ctx, `SELECT created_at FROM mdm_apple_ade_sso_repairs WHERE tenant_id=$1 AND device_id=$2 AND requirement_id=$3 AND id=$4`, scope.TenantID, device, r.ID, before).Scan(&at); err != nil {
			return nil, nil, "", notFound(err)
		}
		stamp, cursor = at, before
	}
	rows, err := s.db.QueryContext(ctx, `SELECT h.id,h.profile_revision_id,h.actor,h.reason,h.created_at FROM mdm_apple_ade_sso_repairs h JOIN mdm_apple_devices d ON d.id=h.device_id AND d.tenant_id=h.tenant_id WHERE h.tenant_id=$1 AND h.device_id=$2 AND h.requirement_id=$3 AND ($4::timestamptz IS NULL OR (h.created_at,h.id)<($4,$5::uuid)) AND ($6=0 OR d.site_id=$6) ORDER BY h.created_at DESC,h.id DESC LIMIT 101`, scope.TenantID, device, r.ID, stamp, cursor, scope.SiteID)
	if err != nil {
		return nil, nil, "", err
	}
	defer rows.Close()
	items := []ADEPlatformSSORepair{}
	for rows.Next() {
		var item ADEPlatformSSORepair
		if err = rows.Scan(&item.ID, &item.ProfileRevisionID, &item.Actor, &item.Reason, &item.CreatedAt); err != nil {
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
