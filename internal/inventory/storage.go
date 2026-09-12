package inventory

import (
	"context"
	"database/sql"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrStorageFilter = ErrReportFilter

type StorageKind string

const (
	PhysicalStorage StorageKind = "physical"
	LogicalStorage  StorageKind = "logical"
)

type StorageFilter struct {
	ReportFilter
	Kind StorageKind
}

func (f StorageFilter) Valid() bool {
	return f.ReportFilter.Valid() && (f.Kind == PhysicalStorage || f.Kind == LogicalStorage)
}

// StorageEntry preserves stored report values. Usage is a reported percentage,
// not a calculation; historical defaults cannot prove that an agent observed it.
type StorageEntry struct {
	ID                                                                  int64
	Name, Model, Serial, Size, Filesystem, Remaining, Volume, BitLocker string
	Usage                                                               *int64
}

type StoragePage struct {
	DeviceID, DeviceName, Organization, Site string
	TenantID, SiteID                         int
	LastContact                              *time.Time
	Entries                                  []StorageEntry
	Next                                     int64
}

// ReadStorage binds current authorization, unambiguous device membership and
// one bounded report page to a transaction that commits its audit before return.
func ReadStorage(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, id string, filter StorageFilter) (*StoragePage, error) {
	if db == nil || permissions == nil || scope.TenantID <= 0 || scope.SiteID < 0 {
		return nil, access.ErrDenied
	}
	if id == "" || len(id) > 255 || !utf8.ValidString(id) || strings.IndexFunc(id, unicode.IsControl) >= 0 {
		return nil, ErrNotFound
	}
	if !filter.Valid() {
		return nil, ErrStorageFilter
	}
	// Only these fixed projections can enter the SQL. Search and cursors remain
	// bound values; the caller cannot select a table or column identifier.
	projection := `SELECT id,device_id AS name,model,serial_number AS serial,size_in_units AS size,
 ''::text AS filesystem,NULL::bigint AS usage,''::text AS remaining,''::text AS volume,''::text AS bitlocker
 FROM physical_disks WHERE agent_physicaldisks=a.oid AND id>$4
 AND ($5::text='' OR strpos(lower(device_id),lower($5))>0 OR strpos(lower(model),lower($5))>0 OR strpos(lower(serial_number),lower($5))>0)`
	if filter.Kind == LogicalStorage {
		projection = `SELECT id,label AS name,''::text AS model,''::text AS serial,size_in_units AS size,
 filesystem,usage,remaining_space_in_units AS remaining,volume_name AS volume,bitlocker_status AS bitlocker
 FROM logical_disks WHERE agent_logicaldisks=a.oid AND id>$4
 AND ($5::text='' OR strpos(lower(label),lower($5))>0 OR strpos(lower(volume_name),lower($5))>0 OR strpos(lower(filesystem),lower($5))>0)`
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ReadDevices, scope); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.oid,COALESCE(NULLIF(a.nickname,''),a.hostname),t.id,t.description,s.id,s.description,a.last_contact,
 p.id,COALESCE(p.name,''),COALESCE(p.model,''),COALESCE(p.serial,''),COALESCE(p.size,''),COALESCE(p.filesystem,''),
 p.usage,COALESCE(p.remaining,''),COALESCE(p.volume,''),COALESCE(p.bitlocker,'')
 FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites s ON s.id=sa.site_id JOIN tenants t ON t.id=s.tenant_sites
 LEFT JOIN LATERAL (`+projection+` ORDER BY id LIMIT 26) p ON true
 WHERE a.oid=$1 AND t.id=$2 AND ($3::bigint=0 OR s.id=$3) AND a.agent_status<>'WaitingForAdmission'
 AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1 ORDER BY p.id`, id, scope.TenantID, scope.SiteID, filter.After, filter.Search)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var page *StoragePage
	for rows.Next() {
		if page == nil {
			page = &StoragePage{}
		}
		var item StorageEntry
		var itemID, usage sql.NullInt64
		var last sql.NullTime
		if err = rows.Scan(&page.DeviceID, &page.DeviceName, &page.TenantID, &page.Organization, &page.SiteID, &page.Site, &last,
			&itemID, &item.Name, &item.Model, &item.Serial, &item.Size, &item.Filesystem, &usage, &item.Remaining, &item.Volume, &item.BitLocker); err != nil {
			return nil, err
		}
		if last.Valid {
			page.LastContact = &last.Time
		}
		if itemID.Valid {
			item.ID = itemID.Int64
			if usage.Valid {
				item.Usage = &usage.Int64
			}
			page.Entries = append(page.Entries, item)
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	if page == nil {
		return nil, ErrNotFound
	}
	if len(page.Entries) > 25 {
		page.Entries = page.Entries[:25]
		page.Next = page.Entries[24].ID
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.storage.read',$4)`, page.TenantID, page.SiteID, actor, page.DeviceID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}
