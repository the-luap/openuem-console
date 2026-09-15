package inventory

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"github.com/open-uem/openuem-console/internal/security/access"
)

// DeviceGroupIntersectionTransaction evaluates an explicitly selected source
// group only within the target site. An organization source requires current
// organization-wide read authority; a site grant cannot substitute for it.
// Callers retain responsibility for action authority, bounded transaction
// lifetime, exact target confirmation and per-device admission.
func DeviceGroupIntersectionTransaction(ctx context.Context, tx *sql.Tx, permissions *access.Store, actor string, sourceScope, targetScope access.Scope, sources DeviceSources, id string, revision int) (*DeviceGroupSnapshot, error) {
	if tx == nil || permissions == nil || targetScope.TenantID <= 0 || targetScope.SiteID <= 0 || sourceScope.TenantID != targetScope.TenantID || sourceScope.SiteID < 0 || (sourceScope.SiteID != 0 && sourceScope.SiteID != targetScope.SiteID) {
		return nil, access.ErrDenied
	}
	if sourceScope == targetScope {
		return DeviceGroupSnapshotTransaction(ctx, tx, permissions, actor, targetScope, sources, id, revision)
	}
	if !canonicalRequestID(id) || revision < 1 || revision > 2147483647 {
		return nil, ErrGroupInvalid
	}
	if err := permissions.AuthorizeTransaction(ctx, tx, actor, access.ReadDevices, sourceScope); err != nil {
		return nil, err
	}
	if err := permissions.AuthorizeTransaction(ctx, tx, actor, access.ReadDevices, targetScope); err != nil {
		return nil, err
	}
	group, err := scanDeviceGroup(tx.QueryRowContext(ctx, `SELECT `+groupColumns+` FROM `+groupJoin+` JOIN tenants t ON t.id=g.tenant_id JOIN sites s ON s.id=$3 AND s.tenant_sites=t.id WHERE g.id=$1 AND g.tenant_id=$2 AND g.site_id=0 FOR SHARE OF g,t,s`, id, sourceScope.TenantID, targetScope.SiteID))
	if err != nil {
		return nil, err
	}
	if group.Revision != revision || group.Archived {
		return nil, ErrGroupConflict
	}
	filter := DeviceFilter{Platform: group.Rule.Platform, Search: group.Rule.Search}
	page, err := queryDevices(ctx, tx, false, targetScope, sources, filter, 100, true, deviceFilterBinding(targetScope, sources, filter))
	if errors.Is(err, ErrDeviceExportTooLarge) {
		return nil, ErrGroupSnapshotLarge
	}
	if err != nil {
		return nil, err
	}
	resource := id + "@" + strconv.Itoa(revision) + "/site:" + strconv.Itoa(targetScope.SiteID)
	if err = recordGroupEvent(ctx, tx, actor, sourceScope, "read", resource); err != nil {
		return nil, err
	}
	return &DeviceGroupSnapshot{Group: group, Entries: page.Entries}, nil
}
