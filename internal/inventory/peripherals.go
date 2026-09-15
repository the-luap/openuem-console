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

var ErrPeripheralsFilter = ErrReportFilter

type PeripheralsKind string

const (
	MonitorReports PeripheralsKind = "monitors"
	PrinterReports PeripheralsKind = "printers"
)

type PeripheralsFilter struct {
	ReportFilter
	Kind PeripheralsKind
}

func (f PeripheralsFilter) Valid() bool {
	return f.ReportFilter.Valid() && (f.Kind == MonitorReports || f.Kind == PrinterReports)
}

// PeripheralsEntry contains only reported display or printer configuration.
// Optional printer flags retain absent evidence instead of becoming false.
type PeripheralsEntry struct {
	ID                                           int64
	Name, Manufacturer, Serial, Week, Year, Port string
	Default, Network, Shared                     *bool
}

type PeripheralsPage struct {
	DeviceID, DeviceName, Organization, Site string
	TenantID, SiteID                         int
	LastContact                              *time.Time
	Entries                                  []PeripheralsEntry
	Next                                     int64
}

// ReadPeripherals binds current authorization, unambiguous device membership and
// one bounded report page to a transaction that commits its audit before return.
func ReadPeripherals(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, id string, filter PeripheralsFilter) (*PeripheralsPage, error) {
	if db == nil || permissions == nil || scope.TenantID <= 0 || scope.SiteID < 0 {
		return nil, access.ErrDenied
	}
	if id == "" || len(id) > 255 || !utf8.ValidString(id) || strings.IndexFunc(id, unicode.IsControl) >= 0 {
		return nil, ErrNotFound
	}
	if !filter.Valid() {
		return nil, ErrPeripheralsFilter
	}
	// Only these fixed projections can enter the SQL. Search and cursors remain
	// bound values; the caller cannot select a table or column identifier.
	projection := `SELECT id,model AS name,manufacturer,serial,week_of_manufacture AS week,year_of_manufacture AS year,
 ''::text AS port,NULL::boolean AS is_default,NULL::boolean AS is_network,NULL::boolean AS is_shared
 FROM monitors WHERE agent_monitors=a.oid AND id>$4
 AND ($5::text='' OR strpos(lower(model),lower($5))>0 OR strpos(lower(manufacturer),lower($5))>0 OR strpos(lower(serial),lower($5))>0)`
	if filter.Kind == PrinterReports {
		projection = `SELECT id,name,''::text AS manufacturer,''::text AS serial,''::text AS week,''::text AS year,
 port,is_default,is_network,is_shared FROM printers WHERE agent_printers=a.oid AND id>$4
 AND ($5::text='' OR strpos(lower(name),lower($5))>0 OR strpos(lower(port),lower($5))>0)`
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
 p.id,COALESCE(p.name,''),COALESCE(p.manufacturer,''),COALESCE(p.serial,''),COALESCE(p.week,''),COALESCE(p.year,''),COALESCE(p.port,''),
 p.is_default,p.is_network,p.is_shared
 FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites s ON s.id=sa.site_id JOIN tenants t ON t.id=s.tenant_sites
 LEFT JOIN LATERAL (`+projection+` ORDER BY id LIMIT 26) p ON true
 WHERE a.oid=$1 AND t.id=$2 AND ($3::bigint=0 OR s.id=$3) AND a.agent_status<>'WaitingForAdmission'
 AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1 ORDER BY p.id`, id, scope.TenantID, scope.SiteID, filter.After, filter.Search)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var page *PeripheralsPage
	for rows.Next() {
		if page == nil {
			page = &PeripheralsPage{}
		}
		var item PeripheralsEntry
		var itemID sql.NullInt64
		var isDefault, network, shared sql.NullBool
		var last sql.NullTime
		if err = rows.Scan(&page.DeviceID, &page.DeviceName, &page.TenantID, &page.Organization, &page.SiteID, &page.Site, &last,
			&itemID, &item.Name, &item.Manufacturer, &item.Serial, &item.Week, &item.Year, &item.Port, &isDefault, &network, &shared); err != nil {
			return nil, err
		}
		if last.Valid {
			page.LastContact = &last.Time
		}
		if itemID.Valid {
			item.ID = itemID.Int64
			if isDefault.Valid {
				item.Default = &isDefault.Bool
			}
			if network.Valid {
				item.Network = &network.Bool
			}
			if shared.Valid {
				item.Shared = &shared.Bool
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.peripherals.read',$4)`, page.TenantID, page.SiteID, actor, page.DeviceID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}
