package apple

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type ADEApplicationChange struct {
	ID, PreviousVersionID, PreviousVersion, VersionID, Version, Actor, Reason string
	CreatedAt                                                                 time.Time
}

// History cursors are resolved only within the selected requirement and device.
func (s *Store) ADEApplicationChanges(ctx context.Context, scope Scope, device, requirement, before string) (*ADEApplication, []ADEApplicationChange, string, error) {
	if _, err := s.Device(ctx, scope, device); err != nil {
		return nil, nil, "", err
	}
	r, err := scanADEApplication(s.db.QueryRowContext(ctx, `SELECT `+adeApplicationColumns+adeApplicationFrom+`WHERE r.tenant_id=$1 AND r.device_id=$2 AND r.id=$3`, scope.TenantID, device, requirement))
	if err != nil {
		return nil, nil, "", err
	}
	var stamp, cursor any
	if before != "" {
		id, e := uuid.Parse(before)
		if e != nil || id == uuid.Nil || id.String() != before {
			return nil, nil, "", ErrMacApp
		}
		var at time.Time
		if err = s.db.QueryRowContext(ctx, `SELECT created_at FROM mdm_apple_ade_app_changes WHERE tenant_id=$1 AND device_id=$2 AND requirement_id=$3 AND id=$4`, scope.TenantID, device, requirement, before).Scan(&at); err != nil {
			return nil, nil, "", notFound(err)
		}
		stamp, cursor = at, before
	}
	rows, err := s.db.QueryContext(ctx, `SELECT c.id,c.previous_version_id,p.version,c.version_id,v.version,c.actor,c.reason,c.created_at FROM mdm_apple_ade_app_changes c JOIN uem_software_versions p ON p.tenant_id=c.tenant_id AND p.id=c.previous_version_id JOIN uem_software_versions v ON v.tenant_id=c.tenant_id AND v.id=c.version_id WHERE c.tenant_id=$1 AND c.device_id=$2 AND c.requirement_id=$3 AND ($4::timestamptz IS NULL OR (c.created_at,c.id)<($4,$5::uuid)) ORDER BY c.created_at DESC,c.id DESC LIMIT 101`, scope.TenantID, device, requirement, stamp, cursor)
	if err != nil {
		return nil, nil, "", err
	}
	defer rows.Close()
	items := []ADEApplicationChange{}
	for rows.Next() {
		var c ADEApplicationChange
		if err = rows.Scan(&c.ID, &c.PreviousVersionID, &c.PreviousVersion, &c.VersionID, &c.Version, &c.Actor, &c.Reason, &c.CreatedAt); err != nil {
			return nil, nil, "", err
		}
		items = append(items, c)
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
