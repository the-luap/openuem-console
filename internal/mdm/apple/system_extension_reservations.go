package apple

import (
	"context"
	"database/sql"
	"fmt"
)

// Assignment holds the native device row. Compare the proposed profile against
// each possible revision of other profiles, without pretending that two
// historical revisions of the same profile are installed simultaneously.
func (s *Store) reserveSystemExtensions(ctx context.Context, tx *sql.Tx, d *Device, p *Profile) error {
	wanted, err := systemExtensionProfileRules(p.Payload, p.Scope, d)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProfilePrerequisite, err)
	}
	if wanted == nil {
		return nil
	}
	if wanted.collisionSensitive() {
		rows, err := tx.QueryContext(ctx, `SELECT profile_revision_id FROM mdm_apple_system_extension_reservations WHERE tenant_id=$1 AND device_id=$2 AND profile_id<>$3 ORDER BY profile_id,revision LIMIT 1001`, d.TenantID, d.ID, p.ID)
		if err != nil {
			return err
		}
		snapshots := []sql.NullString{}
		for rows.Next() {
			var id sql.NullString
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			snapshots = append(snapshots, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(snapshots) > 1000 {
			return fmt.Errorf("%w: verify outstanding system extension profile replacements or removals first", ErrProfilePrerequisite)
		}
		for _, id := range snapshots {
			if !id.Valid {
				return fmt.Errorf("%w: an existing profile has no retained snapshot; verify its replacement or removal before changing system extension rules", ErrProfilePrerequisite)
			}
			previous, err := s.profileRevisionPayload(ctx, tx, d.TenantID, id.String)
			if err != nil {
				return err
			}
			rules, err := systemExtensionProfileRules(previous.Payload, previous.Scope, nil)
			clear(previous.Payload)
			if err != nil {
				return fmt.Errorf("%w: verify replacement or removal of the existing invalid system extension profile", ErrProfilePrerequisite)
			}
			if rules != nil && wanted.conflicts(rules) {
				return fmt.Errorf("%w: another potentially installed profile has conflicting system extension approval or removal rules; verify its replacement or removal first", ErrProfilePrerequisite)
			}
		}
	}
	var snapshot string
	if err = tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_profile_revisions WHERE tenant_id=$1 AND profile_id=$2 AND revision=$3 AND payload_uuid=$4`, d.TenantID, p.ID, p.Revision, p.UUID).Scan(&snapshot); err != nil {
		return notFound(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_system_extension_reservations(tenant_id,device_id,profile_id,revision,profile_revision_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, d.TenantID, d.ID, p.ID, p.Revision, snapshot)
	return err
}

func releaseSystemExtensions(ctx context.Context, tx *sql.Tx, tenant int, device, profile string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM mdm_apple_system_extension_reservations r USING mdm_apple_profile_assignments a WHERE r.tenant_id=$1 AND r.device_id=$2 AND r.profile_id=$3 AND a.tenant_id=r.tenant_id AND a.device_id=r.device_id AND a.profile_id=r.profile_id AND a.status='verified' AND (a.desired='removed' OR r.revision<>a.revision)`, tenant, device, profile)
	return err
}
