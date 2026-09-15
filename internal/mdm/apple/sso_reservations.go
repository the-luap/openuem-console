package apple

import (
	"context"
	"database/sql"
	"fmt"
)

// All callers hold the native device row. System profiles affect every user;
// separate user channels have independent effective profile sets. The only
// cross-channel overlap accepted is Apple's Platform SSO device/user merge for
// the same extension and team. Ordinary duplicate routes remain conflicts.
func (s *Store) reserveSSORoutes(ctx context.Context, tx *sql.Tx, d *Device, user string, p *Profile) error {
	wanted, err := extensibleSSORoutes(p.Payload)
	if err != nil {
		return fmt.Errorf("%w: invalid SSO routing", ErrProfilePrerequisite)
	}
	if len(wanted) == 0 {
		return nil
	}
	var channel any
	if user != "" {
		channel = user
	}
	rows, err := tx.QueryContext(ctx, `SELECT profile_id,revision,profile_revision_id,COALESCE(user_channel_id::text,'') FROM mdm_apple_sso_reservations WHERE tenant_id=$1 AND device_id=$2 AND ($3::uuid IS NULL OR user_channel_id IS NULL OR user_channel_id=$3) AND NOT(profile_id=$4 AND user_channel_id IS NOT DISTINCT FROM $3::uuid) ORDER BY profile_id,revision LIMIT 1001`, d.TenantID, d.ID, channel, p.ID)
	if err != nil {
		return err
	}
	type held struct {
		profile, user string
		revision      int
		snapshot      sql.NullString
	}
	claims := []held{}
	for rows.Next() {
		var r held
		if err = rows.Scan(&r.profile, &r.revision, &r.snapshot, &r.user); err != nil {
			rows.Close()
			return err
		}
		claims = append(claims, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(claims) > 1000 {
		return fmt.Errorf("%w: verify outstanding SSO profile replacements or removals before assigning more profiles", ErrProfilePrerequisite)
	}
	for _, r := range claims {
		if !r.snapshot.Valid {
			return fmt.Errorf("%w: an existing profile has no retained snapshot; verify its replacement or removal before assigning SSO", ErrProfilePrerequisite)
		}
		retained, err := s.profileRevisionPayload(ctx, tx, d.TenantID, r.snapshot.String)
		if err != nil {
			return err
		}
		routes, err := extensibleSSORoutes(retained.Payload)
		clear(retained.Payload)
		if err != nil {
			return fmt.Errorf("%w: verify replacement or removal of an existing invalid SSO configuration", ErrProfilePrerequisite)
		}
		for key, candidate := range wanted {
			prior, exists := routes[key]
			if !exists {
				continue
			}
			merging := (user == "") != (r.user == "") && candidate.Platform && prior.Platform && candidate.Extension != "" && candidate.Team != "" && candidate.Extension == prior.Extension && candidate.Team == prior.Team
			if !merging {
				return fmt.Errorf("%w: an SSO URL or host is reserved by another profile; verify its replacement or removal first", ErrProfilePrerequisite)
			}
		}
	}
	var snapshot string
	if err = tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_profile_revisions WHERE tenant_id=$1 AND profile_id=$2 AND revision=$3 AND payload_uuid=$4`, d.TenantID, p.ID, p.Revision, p.UUID).Scan(&snapshot); err != nil {
		return notFound(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_sso_reservations(tenant_id,device_id,user_channel_id,profile_id,revision,profile_revision_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, d.TenantID, d.ID, channel, p.ID, p.Revision, snapshot)
	return err
}

// Call only for an assignment verified by a newly accepted ProfileList query.
// Acceptance of InstallProfile/RemoveProfile alone never releases old routes.
func releaseSSORoutes(ctx context.Context, tx *sql.Tx, tenant int, device, user, profile string) error {
	if user == "" {
		_, err := tx.ExecContext(ctx, `DELETE FROM mdm_apple_sso_reservations r USING mdm_apple_profile_assignments a WHERE r.tenant_id=$1 AND r.device_id=$2 AND r.user_channel_id IS NULL AND r.profile_id=$3 AND a.tenant_id=r.tenant_id AND a.device_id=r.device_id AND a.profile_id=r.profile_id AND a.status='verified' AND (a.desired='removed' OR r.revision<>a.revision)`, tenant, device, profile)
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM mdm_apple_sso_reservations r USING mdm_apple_user_assignments a WHERE r.tenant_id=$1 AND r.device_id=$2 AND r.user_channel_id=$3 AND r.profile_id=$4 AND a.tenant_id=r.tenant_id AND a.device_id=r.device_id AND a.user_channel_id=r.user_channel_id AND a.profile_id=r.profile_id AND a.status='verified' AND (a.desired='removed' OR r.revision<>a.revision)`, tenant, device, user, profile)
	return err
}
