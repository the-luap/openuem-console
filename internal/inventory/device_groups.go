package inventory

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var (
	ErrGroupInvalid  = errors.New("invalid device group")
	ErrGroupConflict = errors.New("device group revision changed")
	ErrGroupLimit    = errors.New("device group scope limit reached")
)

// DeviceGroupRule is a conjunction of the platform filter and a literal,
// case-insensitive substring across name, serial, model and OS version.
// Scope and management-source enablement cannot be supplied by a rule.
type DeviceGroupRule struct{ Platform, Search string }

type DeviceGroupDefinition struct {
	Name, Description string
	Rule              DeviceGroupRule
	Archived          bool
}

func (d DeviceGroupDefinition) Valid() bool {
	text := func(s string, max int) bool {
		return len(s) <= max && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
	}
	return strings.TrimSpace(d.Name) != "" && text(d.Name, 120) && text(d.Description, 1024) && (DeviceFilter{Platform: d.Rule.Platform, Search: d.Rule.Search}).Valid()
}

type DeviceGroup struct {
	ID string
	access.Scope
	Revision int
	DeviceGroupDefinition
	Actor     string
	CreatedAt time.Time
}

type DeviceGroupPage struct {
	Groups []DeviceGroup
	Next   string
}
type DeviceGroupInspection struct {
	Group         DeviceGroup
	Members       *DevicePage
	History       []DeviceGroup
	HistoryBefore int
}
type DeviceGroupPosition struct {
	Revision      int
	After         string
	HistoryBefore int
}

// Scope locks prevent a concurrent site move/deletion from silently changing the
// meaning of a persisted group. Each group belongs to exactly one route scope.
func beginGroupTransaction(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, capability access.Capability) (*sql.Tx, error) {
	if db == nil || permissions == nil || scope.TenantID <= 0 || scope.SiteID < 0 {
		return nil, access.ErrDenied
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*sql.Tx, error) {
		tx.Rollback()
		return nil, err
	}
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, capability, scope); err != nil {
		return fail(err)
	}
	var id int
	if scope.SiteID == 0 {
		err = tx.QueryRowContext(ctx, `SELECT id FROM tenants WHERE id=$1 FOR SHARE`, scope.TenantID).Scan(&id)
	} else {
		err = tx.QueryRowContext(ctx, `SELECT s.id FROM sites s JOIN tenants t ON t.id=s.tenant_sites WHERE t.id=$1 AND s.id=$2 FOR SHARE OF s,t`, scope.TenantID, scope.SiteID).Scan(&id)
	}
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return fail(err)
	}
	return tx, nil
}

const groupColumns = `g.id,g.tenant_id,g.site_id,r.revision,r.name,r.description,r.platform,r.search,r.archived,r.actor,r.created_at`
const groupJoin = `uem_device_groups g JOIN uem_device_group_revisions r ON r.group_id=g.id AND r.revision=g.revision`

type groupScanner interface{ Scan(...any) error }

func scanDeviceGroup(row groupScanner) (DeviceGroup, error) {
	var g DeviceGroup
	err := row.Scan(&g.ID, &g.TenantID, &g.SiteID, &g.Revision, &g.Name, &g.Description, &g.Rule.Platform, &g.Rule.Search, &g.Archived, &g.Actor, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return g, err
}
func recordGroupEvent(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope, action, resource string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,$4,$5)`, scope.TenantID, scope.SiteID, actor, "inventory.groups."+action, resource)
	return err
}

// SaveDeviceGroup creates a stable identity or appends a new definition. A
// historical revision is never rewritten; expectedRevision must be current.
// Archiving and reactivation use the same revision check and audit transaction.
func SaveDeviceGroup(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, id string, expectedRevision int, definition DeviceGroupDefinition) (*DeviceGroup, error) {
	if !definition.Valid() || expectedRevision < 0 || expectedRevision >= 2147483647 || (id == "" && expectedRevision != 0) || (id != "" && (!canonicalRequestID(id) || expectedRevision == 0)) {
		return nil, ErrGroupInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := beginGroupTransaction(ctx, db, permissions, actor, scope, access.ManageDeviceGroups)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	action := "revise"
	if id == "" {
		// One lock serializes admission to this fixed limit across all replicas.
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629903,hashtext($1))`, strconv.Itoa(scope.TenantID)+":"+strconv.Itoa(scope.SiteID)); err != nil {
			return nil, err
		}
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM uem_device_groups WHERE tenant_id=$1 AND site_id=$2`, scope.TenantID, scope.SiteID).Scan(&count); err != nil {
			return nil, err
		}
		if count >= 1000 {
			return nil, ErrGroupLimit
		}
		id = uuid.NewString()
		action = "create"
		_, err = tx.ExecContext(ctx, `INSERT INTO uem_device_groups(id,tenant_id,site_id,revision) VALUES($1,$2,$3,1)`, id, scope.TenantID, scope.SiteID)
	} else {
		var revision int
		err = tx.QueryRowContext(ctx, `SELECT revision FROM uem_device_groups WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR UPDATE`, id, scope.TenantID, scope.SiteID).Scan(&revision)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		if revision != expectedRevision {
			return nil, ErrGroupConflict
		}
		_, err = tx.ExecContext(ctx, `UPDATE uem_device_groups SET revision=revision+1 WHERE id=$1`, id)
	}
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_device_group_revisions(group_id,revision,name,description,platform,search,archived,actor) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, expectedRevision+1, definition.Name, definition.Description, definition.Rule.Platform, definition.Rule.Search, definition.Archived, actor)
	if err != nil {
		return nil, err
	}
	group, err := scanDeviceGroup(tx.QueryRowContext(ctx, `SELECT `+groupColumns+` FROM `+groupJoin+` WHERE g.id=$1`, id))
	if err != nil {
		return nil, err
	}
	if err = recordGroupEvent(ctx, tx, actor, scope, action, id+"@"+strconv.Itoa(group.Revision)); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &group, nil
}

func ListDeviceGroups(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, after string) (*DeviceGroupPage, error) {
	if after != "" && !canonicalRequestID(after) {
		return nil, ErrGroupInvalid
	}
	if after == "" {
		after = uuid.Nil.String()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := beginGroupTransaction(ctx, db, permissions, actor, scope, access.ReadDevices)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT `+groupColumns+` FROM `+groupJoin+` WHERE g.tenant_id=$1 AND g.site_id=$2 AND g.id>$3::uuid ORDER BY g.id LIMIT 26`, scope.TenantID, scope.SiteID, after)
	if err != nil {
		return nil, err
	}
	page := &DeviceGroupPage{Groups: []DeviceGroup{}}
	for rows.Next() {
		g, err := scanDeviceGroup(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		page.Groups = append(page.Groups, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(page.Groups) > 25 {
		page.Groups = page.Groups[:25]
		page.Next = page.Groups[24].ID
	}
	if err = recordGroupEvent(ctx, tx, actor, scope, "list", "groups"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}

// InspectDeviceGroup holds the current definition while evaluating one fresh
// inventory snapshot. Membership is a read-only preview, never an assignment.
func InspectDeviceGroup(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, sources DeviceSources, id string, position DeviceGroupPosition) (*DeviceGroupInspection, error) {
	if !canonicalRequestID(id) || position.Revision < 0 || position.Revision > 2147483647 || position.HistoryBefore < 0 || position.HistoryBefore > 2147483647 || (position.After != "" || position.HistoryBefore != 0) && position.Revision == 0 || len(position.After) > 8192 {
		return nil, ErrGroupInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := beginGroupTransaction(ctx, db, permissions, actor, scope, access.ReadDevices)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	group, err := scanDeviceGroup(tx.QueryRowContext(ctx, `SELECT `+groupColumns+` FROM `+groupJoin+` WHERE g.id=$1 AND g.tenant_id=$2 AND g.site_id=$3 FOR SHARE OF g`, id, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, err
	}
	if position.Revision != 0 && position.Revision != group.Revision {
		return nil, ErrGroupConflict
	}
	result := &DeviceGroupInspection{Group: group, Members: &DevicePage{Entries: []DeviceEntry{}}, History: []DeviceGroup{}}
	if !group.Archived {
		filter := DeviceFilter{Platform: group.Rule.Platform, Search: group.Rule.Search, After: position.After}
		// Ambiguous desktop memberships never become dynamic group targets, even
		// for the server administrator who can inspect them in the repair inventory.
		binding := deviceFilterBinding(scope, sources, filter) + ":" + id + ":" + strconv.Itoa(group.Revision)
		result.Members, err = queryDevices(ctx, tx, false, scope, sources, filter, 25, false, binding)
		if err != nil {
			return nil, err
		}
	} else if position.After != "" {
		return nil, ErrGroupInvalid
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+groupColumns+` FROM uem_device_groups g JOIN uem_device_group_revisions r ON r.group_id=g.id WHERE g.id=$1 AND ($2::integer=0 OR r.revision<$2) ORDER BY r.revision DESC LIMIT 26`, id, position.HistoryBefore)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		g, err := scanDeviceGroup(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		result.History = append(result.History, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(result.History) > 25 {
		result.History = result.History[:25]
		result.HistoryBefore = result.History[24].Revision
	}
	if err = recordGroupEvent(ctx, tx, actor, scope, "read", id+"@"+strconv.Itoa(group.Revision)); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
