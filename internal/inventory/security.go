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

var ErrSecurityFilter = ErrReportFilter

type SecurityFilter = ReportFilter

// SecurityUpdateEntry contains stored update history, without claiming current
// installation, patch completeness or the safety of a reported support URL.
type SecurityUpdateEntry struct {
	ID                int64
	Title, SupportURL string
	Date              *time.Time
}

type SecurityPage struct {
	DeviceID, DeviceName, Organization, Site string
	TenantID, SiteID                         int
	LastContact                              *time.Time
	AntivirusName                            string
	AntivirusActive, AntivirusUpdated        *bool
	UpdateStatus                             string
	LastInstall, LastSearch                  *time.Time
	PendingUpdates                           *bool
	Entries                                  []SecurityUpdateEntry
	Next                                     int64
}

// ReadSecurity selects current membership and one bounded report page in the
// same SQL statement, under transaction-bound authorization and a committed
// read audit. Report cursors cannot retain access after a device changes scope.
func ReadSecurity(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, id string, filter SecurityFilter) (*SecurityPage, error) {
	if db == nil || permissions == nil || scope.TenantID <= 0 || scope.SiteID < 0 {
		return nil, access.ErrDenied
	}
	if id == "" || len(id) > 255 || !utf8.ValidString(id) || strings.IndexFunc(id, unicode.IsControl) >= 0 {
		return nil, ErrNotFound
	}
	if !filter.Valid() {
		return nil, ErrSecurityFilter
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
 COALESCE(av.name,''),av.is_active,av.is_updated,COALESCE(su.system_update_status,''),su.last_install,su.last_search,su.pending_updates,
 p.id,COALESCE(p.title,''),p.date,COALESCE(p.support_url,'')
 FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites s ON s.id=sa.site_id JOIN tenants t ON t.id=s.tenant_sites
 LEFT JOIN antiviri av ON av.agent_antivirus=a.oid
 LEFT JOIN system_updates su ON su.agent_systemupdate=a.oid
 LEFT JOIN LATERAL (SELECT id,title,date,support_url
 FROM updates WHERE agent_updates=a.oid AND id>$4
 AND ($5::text='' OR strpos(lower(title),lower($5))>0 OR strpos(lower(support_url),lower($5))>0)
 ORDER BY id LIMIT 26) p ON true
 WHERE a.oid=$1 AND t.id=$2 AND ($3::bigint=0 OR s.id=$3) AND a.agent_status<>'WaitingForAdmission'
 AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1 ORDER BY p.id`, id, scope.TenantID, scope.SiteID, filter.After, filter.Search)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var page *SecurityPage
	for rows.Next() {
		if page == nil {
			page = &SecurityPage{}
		}
		var item SecurityUpdateEntry
		var itemID sql.NullInt64
		var last sql.NullTime
		if err = rows.Scan(&page.DeviceID, &page.DeviceName, &page.TenantID, &page.Organization, &page.SiteID, &page.Site, &last,
			&page.AntivirusName, &page.AntivirusActive, &page.AntivirusUpdated, &page.UpdateStatus, &page.LastInstall, &page.LastSearch, &page.PendingUpdates,
			&itemID, &item.Title, &item.Date, &item.SupportURL); err != nil {
			return nil, err
		}
		if last.Valid {
			page.LastContact = &last.Time
		}
		if itemID.Valid {
			item.ID = itemID.Int64
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.security.read',$4)`, page.TenantID, page.SiteID, actor, page.DeviceID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}
