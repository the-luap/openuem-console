// Package inventory provides authorized projections of existing device reports.
package inventory

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrNotFound = errors.New("inventory device not found")

// Desktop contains only fields intended for device readers. Agent settings,
// notes, task output, remote access data and signed-in user data are excluded.
type Desktop struct {
	ID, Name, Hostname, Platform, Status, EndpointType, IP, MAC string
	Organization, Site                                          string
	TenantID, SiteID                                            int
	FirstContact, LastContact                                   *time.Time
	Hardware                                                    *Hardware
	OperatingSystem                                             *OperatingSystem
}

type Hardware struct {
	Manufacturer, Model, Serial, Processor, Architecture string
	Memory                                               uint64
	Cores                                                int64
}

type OperatingSystem struct {
	Version, Edition, Architecture string
}

// ReadDesktop rechecks current grants and commits the read audit before returning
// data. One SQL statement reads both membership and inventory, so concurrent site
// moves cannot mix an old authorization scope with a new inventory snapshot.
func ReadDesktop(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, id string) (*Desktop, error) {
	if db == nil || permissions == nil || scope.TenantID <= 0 || scope.SiteID < 0 {
		return nil, access.ErrDenied
	}
	if id == "" || len(id) > 255 || !utf8.ValidString(id) || strings.IndexFunc(id, unicode.IsControl) >= 0 {
		return nil, ErrNotFound
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
	var d Desktop
	var hardware Hardware
	var os OperatingSystem
	var hardwareID, osID sql.NullInt64
	var first, last sql.NullTime
	// A legacy agent must have exactly one site, including sites outside the
	// requested scope. Filtering edges first would hide ambiguous assignments.
	err = tx.QueryRowContext(ctx, `SELECT a.oid,COALESCE(NULLIF(a.nickname,''),a.hostname),a.hostname,a.os,a.agent_status,COALESCE(a.endpoint_type,''),a.ip,a.mac,
 a.first_contact,a.last_contact,t.id,t.description,s.id,s.description,
 c.id,COALESCE(c.manufacturer,''),COALESCE(c.model,''),COALESCE(c.serial,''),COALESCE(c.processor,''),COALESCE(c.processor_arch,''),COALESCE(c.memory,0),COALESCE(c.processor_cores,0),
 o.id,COALESCE(o.version,''),COALESCE(o.edition,''),COALESCE(o.arch,'')
 FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid
 JOIN sites s ON s.id=sa.site_id JOIN tenants t ON t.id=s.tenant_sites
 LEFT JOIN computers c ON c.agent_computer=a.oid
 LEFT JOIN operating_systems o ON o.agent_operatingsystem=a.oid
 WHERE a.oid=$1 AND t.id=$2 AND ($3::bigint=0 OR s.id=$3)
 AND a.agent_status<>'WaitingForAdmission'
 AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1`, id, scope.TenantID, scope.SiteID).Scan(
		&d.ID, &d.Name, &d.Hostname, &d.Platform, &d.Status, &d.EndpointType, &d.IP, &d.MAC,
		&first, &last, &d.TenantID, &d.Organization, &d.SiteID, &d.Site,
		&hardwareID, &hardware.Manufacturer, &hardware.Model, &hardware.Serial, &hardware.Processor, &hardware.Architecture, &hardware.Memory, &hardware.Cores,
		&osID, &os.Version, &os.Edition, &os.Architecture)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if first.Valid {
		d.FirstContact = &first.Time
	}
	if last.Valid {
		d.LastContact = &last.Time
	}
	if hardwareID.Valid {
		d.Hardware = &hardware
	}
	if osID.Valid {
		d.OperatingSystem = &os
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.desktop.read',$4)`, d.TenantID, d.SiteID, actor, d.ID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &d, nil
}
