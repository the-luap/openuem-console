package inventory

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrGroupSnapshotLarge = errors.New("device group snapshot exceeds supported bounds")

type DeviceGroupSnapshot struct {
	Group   DeviceGroup
	Entries []DeviceEntry
}

// DeviceGroupSnapshotTransaction reads every member of one current revision in
// the caller's transaction. It keeps the group locked until that transaction
// ends. There is no implicit truncation: action previews support at most 100
// total members, with the same metadata bounds as inventory exports. The caller
// must separately authorize its action and validate every selected device.
func DeviceGroupSnapshotTransaction(ctx context.Context, tx *sql.Tx, permissions *access.Store, actor string, scope access.Scope, sources DeviceSources, id string, revision int) (*DeviceGroupSnapshot, error) {
	if tx == nil || permissions == nil || scope.TenantID <= 0 || scope.SiteID <= 0 {
		return nil, access.ErrDenied
	}
	if !canonicalRequestID(id) || revision < 1 || revision > 2147483647 {
		return nil, ErrGroupInvalid
	}
	if err := permissions.AuthorizeTransaction(ctx, tx, actor, access.ReadDevices, scope); err != nil {
		return nil, err
	}
	group, err := scanDeviceGroup(tx.QueryRowContext(ctx, `SELECT `+groupColumns+` FROM `+groupJoin+` JOIN sites s ON s.id=g.site_id AND s.tenant_sites=g.tenant_id WHERE g.id=$1 AND g.tenant_id=$2 AND g.site_id=$3 FOR SHARE OF g,s`, id, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, err
	}
	if group.Revision != revision || group.Archived {
		return nil, ErrGroupConflict
	}
	filter := DeviceFilter{Platform: group.Rule.Platform, Search: group.Rule.Search}
	page, err := queryDevices(ctx, tx, false, scope, sources, filter, 100, true, deviceFilterBinding(scope, sources, filter))
	if errors.Is(err, ErrDeviceExportTooLarge) {
		return nil, ErrGroupSnapshotLarge
	}
	if err != nil {
		return nil, err
	}
	if err = recordGroupEvent(ctx, tx, actor, scope, "read", id+"@"+strconv.Itoa(revision)); err != nil {
		return nil, err
	}
	return &DeviceGroupSnapshot{Group: group, Entries: page.Entries}, nil
}
