package inventory

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/open-uem/openuem-console/internal/security/access"
)

// DeviceSources comes from enabled server stores, never from request parameters.
type DeviceSources struct{ Apple, Windows bool }

type DeviceFilter struct{ Platform, Search, After string }

type DeviceEntry struct {
	Kind, ID, Name, Platform, OSVersion, Serial, Model, Status, AgentStatus string
	TenantID, SiteID                                                        int
	LastSeen                                                                *time.Time
	sortName                                                                string
}

type DevicePage struct {
	Entries []DeviceEntry
	Next    string
}

type deviceCursor struct {
	Binding, Name, Kind, ID string
}

func (f DeviceFilter) Valid() bool {
	switch f.Platform {
	case "", "apple", "ios", "ipados", "macos", "windows", "linux", "unknown":
	default:
		return false
	}
	return len(f.Search) <= 256 && utf8.ValidString(f.Search) && strings.IndexFunc(f.Search, unicode.IsControl) < 0 && len(f.After) <= 8192
}

func deviceFilterBinding(scope access.Scope, sources DeviceSources, f DeviceFilter) string {
	encoded, _ := json.Marshal([]any{1, scope.TenantID, scope.SiteID, sources, f.Platform, f.Search})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// ReadDevices filters and orders one database snapshot before returning at most
// 25 safe rows. Current grants and the read audit share the transaction. A cursor
// is only a position within this query; it never carries permission to read data.
func ReadDevices(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, sources DeviceSources, filter DeviceFilter) (*DevicePage, error) {
	if db == nil || permissions == nil || scope.TenantID <= 0 || scope.SiteID < 0 {
		return nil, access.ErrDenied
	}
	if !filter.Valid() {
		return nil, ErrReportFilter
	}
	binding := deviceFilterBinding(scope, sources, filter)
	cursor := deviceCursor{Binding: binding}
	if filter.After != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(filter.After)
		if err != nil || json.Unmarshal(decoded, &cursor) != nil || cursor.Binding != binding || cursor.ID == "" || len(cursor.ID) > 255 || len(cursor.Name) > 4096 {
			return nil, ErrReportFilter
		}
		switch cursor.Kind {
		case "desktop", "apple", "mac", "windows":
		default:
			return nil, ErrReportFilter
		}
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
	// Administrators retain the legacy list's ability to inspect ambiguous site
	// assignments. The shared permission lock above keeps this role check current.
	var administrator bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_access_grants WHERE user_id=$1 AND role='administrator')`, actor).Scan(&administrator); err != nil {
		return nil, err
	}
	linked := false
	if sources.Apple {
		if err = tx.QueryRowContext(ctx, `SELECT to_regclass('uem_mac_devices') IS NOT NULL AND to_regclass('uem_mac_agent_channels') IS NOT NULL AND to_regclass('uem_mac_mdm_channels') IS NOT NULL`).Scan(&linked); err != nil {
			return nil, err
		}
	}
	branches := []string{desktopDeviceRows}
	if linked {
		branches[0] += ` AND NOT EXISTS(SELECT 1 FROM uem_mac_agent_channels ac WHERE ac.device_id::text=a.oid AND ac.tenant_id=t.id AND ac.site_id=s.id)`
	}
	if sources.Apple {
		branch := appleDeviceRows
		if linked {
			branch += ` AND NOT EXISTS(SELECT 1 FROM uem_mac_mdm_channels mc WHERE mc.device_id=d.id AND mc.tenant_id=d.tenant_id AND mc.site_id=d.site_id)`
			branches = append(branches, macDeviceRows)
		}
		branches = append(branches, branch)
	}
	if sources.Windows {
		branches = append(branches, windowsDeviceRows)
	}
	query := `WITH devices(kind,id,tenant_id,site_id,name,platform,os_version,serial,model,status,agent_status,last_seen,valid) AS (` + strings.Join(branches, " UNION ALL ") + `),
 filtered AS (SELECT *,lower(name) COLLATE "C" AS sort_name FROM devices
 WHERE ($4='' OR platform=$4 OR ($4='apple' AND kind IN ('apple','mac')))
 AND position(lower($3) in lower(name||' '||serial||' '||model||' '||os_version))>0)
 SELECT kind,id,tenant_id,site_id,name,platform,os_version,serial,model,status,agent_status,last_seen,valid,sort_name FROM filtered
 WHERE NOT $8::boolean OR (sort_name,kind COLLATE "C",id COLLATE "C")>($5 COLLATE "C",$6 COLLATE "C",$7 COLLATE "C")
 ORDER BY sort_name,kind COLLATE "C",id COLLATE "C" LIMIT 26`
	rows, err := tx.QueryContext(ctx, query, scope.TenantID, scope.SiteID, filter.Search, filter.Platform, cursor.Name, cursor.Kind, cursor.ID, filter.After != "", administrator)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &DevicePage{Entries: []DeviceEntry{}}
	for rows.Next() {
		var d DeviceEntry
		var valid bool
		if err = rows.Scan(&d.Kind, &d.ID, &d.TenantID, &d.SiteID, &d.Name, &d.Platform, &d.OSVersion, &d.Serial, &d.Model, &d.Status, &d.AgentStatus, &d.LastSeen, &valid, &d.sortName); err != nil {
			return nil, err
		}
		if !valid {
			return nil, errors.New("device inventory lifecycle evidence is inconsistent")
		}
		page.Entries = append(page.Entries, d)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(page.Entries) > 25 {
		page.Entries = page.Entries[:25]
		last := page.Entries[24]
		encoded, err := json.Marshal(deviceCursor{Binding: binding, Name: last.sortName, Kind: last.Kind, ID: last.ID})
		if err != nil || len(last.sortName) > 4096 || len(last.ID) > 255 {
			return nil, errors.New("device inventory cursor exceeds supported metadata bounds")
		}
		page.Next = base64.RawURLEncoding.EncodeToString(encoded)
		if len(page.Next) > 8192 {
			return nil, errors.New("device inventory cursor exceeds supported metadata bounds")
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.devices.list','devices')`, scope.TenantID, scope.SiteID, actor); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}

const desktopDeviceRows = `SELECT 'desktop',a.oid,t.id,s.id,COALESCE(NULLIF(a.nickname,''),a.hostname),
 CASE lower(trim(a.os)) WHEN 'windows' THEN 'windows' WHEN 'linux' THEN 'linux' WHEN 'darwin' THEN 'macos' WHEN 'macos' THEN 'macos' WHEN 'mac os x' THEN 'macos' ELSE 'unknown' END,
 COALESCE(o.version,''),COALESCE(c.serial,''),COALESCE(c.model,''),'agent','',a.last_contact,true
 FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites s ON s.id=sa.site_id JOIN tenants t ON t.id=s.tenant_sites
 LEFT JOIN computers c ON c.agent_computer=a.oid LEFT JOIN operating_systems o ON o.agent_operatingsystem=a.oid
 WHERE t.id=$1 AND ($2::bigint=0 OR s.id=$2) AND a.agent_status<>'WaitingForAdmission'
 AND ($9::boolean OR (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1)
 AND s.id=(SELECT min(s2.id) FROM site_agents sa2 JOIN sites s2 ON s2.id=sa2.site_id WHERE sa2.agent_id=a.oid AND s2.tenant_sites=$1 AND ($2::bigint=0 OR s2.id=$2))`

const appleDeviceRows = `SELECT 'apple',d.id::text,d.tenant_id,d.site_id,d.name,d.platform,d.os_version,d.serial_number,d.model,d.status,'',d.last_seen,true
 FROM mdm_apple_devices d JOIN sites s ON s.id=d.site_id AND s.tenant_sites=d.tenant_id
 WHERE d.tenant_id=$1 AND ($2::bigint=0 OR d.site_id=$2)`

const macDeviceRows = `SELECT 'mac',m.id::text,m.tenant_id,m.site_id,COALESCE(NULLIF(d.name,''),i.display_name),'macos',d.os_version,m.serial,m.model,
 CASE WHEN d.status='enrolled' AND d.certificate_expires_at<=clock_timestamp() THEN 'expired' ELSE d.status END,
 CASE WHEN i.revoked_at IS NOT NULL THEN 'revoked' WHEN i.certificate_expires_at<=clock_timestamp() THEN 'expired'
 WHEN h.device_id IS NULL THEN 'unknown' WHEN h.model<>m.model OR h.serial<>m.serial OR h.platform_uuid<>m.platform_uuid OR h.provisioning_udid<>m.provisioning_udid THEN 'conflict'
 WHEN h.observed_at<clock_timestamp()-interval '24 hours' THEN 'stale' ELSE 'enrolled' END,
 greatest(d.last_seen,h.observed_at),true
 FROM uem_mac_devices m JOIN sites s ON s.id=m.site_id AND s.tenant_sites=m.tenant_id
 JOIN uem_mac_mdm_channels mc ON mc.entity_id=m.id AND mc.retired_at IS NULL
 JOIN mdm_apple_devices d ON d.id=mc.device_id AND d.tenant_id=m.tenant_id AND d.site_id=m.site_id
 JOIN uem_mac_agent_channels ac ON ac.entity_id=m.id AND ac.retired_at IS NULL
 JOIN uem_agent_identities i ON i.id=ac.device_id AND i.tenant_id=m.tenant_id AND i.site_id=m.site_id
 LEFT JOIN uem_agent_hardware h ON h.device_id=i.id
 WHERE m.tenant_id=$1 AND ($2::bigint=0 OR m.site_id=$2)`

// Keep the same current-certificate selection and disconnection consistency
// check as the native Windows console. A pending renewal is not current identity.
const windowsDeviceRows = `SELECT 'windows',d.id::text,d.tenant_id,d.site_id,d.device_name,'windows',d.os_version,'','',
 CASE WHEN u.received_at IS NOT NULL THEN 'native_disconnected' WHEN d.revoked_at IS NOT NULL OR c.revoked_at IS NOT NULL THEN 'native_revoked'
 WHEN c.expires_at<=clock_timestamp() THEN 'native_expired' ELSE 'native_issued' END,'',NULL::timestamptz,
 (u.received_at IS NULL OR d.revoked_at IS NOT NULL AND d.revoked_at=u.received_at)
 FROM mdm_windows_devices d JOIN mdm_windows_enrollments e ON e.device_id=d.id AND e.invitation_id=d.invitation_id AND e.tenant_id=d.tenant_id AND e.site_id=d.site_id
 JOIN mdm_windows_device_certificates c ON c.device_id=d.id AND c.tenant_id=d.tenant_id AND c.site_id=d.site_id
 AND (c.id=e.certificate_id OR EXISTS(SELECT 1 FROM mdm_windows_certificate_renewals r WHERE r.renewed_certificate_id=c.id AND r.device_id=d.id AND r.tenant_id=d.tenant_id AND r.site_id=d.site_id AND r.phase='confirmed'))
 AND NOT EXISTS(SELECT 1 FROM mdm_windows_certificate_renewals r WHERE r.source_certificate_id=c.id AND r.phase='confirmed')
 JOIN sites s ON s.id=d.site_id AND s.tenant_sites=d.tenant_id
 LEFT JOIN mdm_windows_unenrollment_reports u ON u.device_id=d.id AND u.tenant_id=d.tenant_id AND u.site_id=d.site_id
 WHERE d.tenant_id=$1 AND ($2::bigint=0 OR d.site_id=$2)`
