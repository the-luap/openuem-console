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

var ErrNetworkFilter = ErrReportFilter

type NetworkFilter = ReportFilter

// NetworkEntry contains reported adapter configuration only. Optional flags
// retain missing report evidence instead of converting it to an observed false.
type NetworkEntry struct {
	ID                                                        int64
	Name, MAC, Addresses, Subnet, Gateway, DNS, Domain, Speed string
	DHCPEnabled, Virtual                                      *bool
}

type NetworkPage struct {
	DeviceID, DeviceName, Organization, Site string
	TenantID, SiteID                         int
	LastContact                              *time.Time
	Entries                                  []NetworkEntry
	Next                                     int64
}

// ReadNetwork selects current membership and one bounded report page in the
// same SQL statement, under transaction-bound authorization and a committed
// read audit. Report cursors cannot retain access after a device changes scope.
func ReadNetwork(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, id string, filter NetworkFilter) (*NetworkPage, error) {
	if db == nil || permissions == nil || scope.TenantID <= 0 || scope.SiteID < 0 {
		return nil, access.ErrDenied
	}
	if id == "" || len(id) > 255 || !utf8.ValidString(id) || strings.IndexFunc(id, unicode.IsControl) >= 0 {
		return nil, ErrNotFound
	}
	if !filter.Valid() {
		return nil, ErrNetworkFilter
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
 p.id,COALESCE(p.name,''),COALESCE(p.mac_address,''),COALESCE(p.addresses,''),COALESCE(p.subnet,''),COALESCE(p.default_gateway,''),
 COALESCE(p.dns_servers,''),COALESCE(p.dns_domain,''),COALESCE(p.speed,''),p.dhcp_enabled,p.virtual
 FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites s ON s.id=sa.site_id JOIN tenants t ON t.id=s.tenant_sites
 LEFT JOIN LATERAL (SELECT id,name,mac_address,addresses,subnet,default_gateway,dns_servers,dns_domain,speed,dhcp_enabled,virtual
 FROM network_adapters WHERE agent_networkadapters=a.oid AND id>$4
 AND ($5::text='' OR strpos(lower(name),lower($5))>0 OR strpos(lower(mac_address),lower($5))>0 OR strpos(lower(addresses),lower($5))>0)
 ORDER BY id LIMIT 26) p ON true
 WHERE a.oid=$1 AND t.id=$2 AND ($3::bigint=0 OR s.id=$3) AND a.agent_status<>'WaitingForAdmission'
 AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1 ORDER BY p.id`, id, scope.TenantID, scope.SiteID, filter.After, filter.Search)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var page *NetworkPage
	for rows.Next() {
		if page == nil {
			page = &NetworkPage{}
		}
		var item NetworkEntry
		var itemID sql.NullInt64
		var last sql.NullTime
		var dhcp, virtual sql.NullBool
		if err = rows.Scan(&page.DeviceID, &page.DeviceName, &page.TenantID, &page.Organization, &page.SiteID, &page.Site, &last,
			&itemID, &item.Name, &item.MAC, &item.Addresses, &item.Subnet, &item.Gateway, &item.DNS, &item.Domain, &item.Speed, &dhcp, &virtual); err != nil {
			return nil, err
		}
		if last.Valid {
			page.LastContact = &last.Time
		}
		if itemID.Valid {
			item.ID = itemID.Int64
			if dhcp.Valid {
				item.DHCPEnabled = &dhcp.Bool
			}
			if virtual.Valid {
				item.Virtual = &virtual.Bool
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.network.read',$4)`, page.TenantID, page.SiteID, actor, page.DeviceID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}
