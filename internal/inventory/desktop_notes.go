package inventory

import (
	"context"
	"database/sql"
	"errors"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

const MaxDeviceNotesBytes = 64 << 10

var ErrDeviceNotesInvalid = errors.New("invalid device notes or revision")
var ErrDeviceNotesConflict = errors.New("device notes changed; review the current notes before saving")

// DeviceNotes deliberately requires a stronger capability than inventory reads.
// Neither note contents nor a content hash are copied into the audit log.
type DeviceNotes struct {
	DeviceID, DeviceName, Notes, Revision string
	TenantID, SiteID                      int
}

func ValidDeviceNotes(notes string) bool {
	if len(notes) > MaxDeviceNotesBytes || !utf8.ValidString(notes) {
		return false
	}
	for _, r := range notes {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

func ReadDeviceNotes(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, deviceID string) (*DeviceNotes, error) {
	return deviceNotes(ctx, db, permissions, actor, scope, deviceID, "", nil)
}

func UpdateDeviceNotes(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, deviceID, revision, notes string) (*DeviceNotes, error) {
	id, err := uuid.Parse(revision)
	if err != nil || id == uuid.Nil || id.String() != revision || !ValidDeviceNotes(notes) {
		return nil, ErrDeviceNotesInvalid
	}
	return deviceNotes(ctx, db, permissions, actor, scope, deviceID, revision, &notes)
}

func deviceNotes(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, deviceID, revision string, replacement *string) (*DeviceNotes, error) {
	if !ValidReportDeviceID(deviceID) {
		return nil, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginGroupTransaction(ctx, db, permissions, actor, scope, access.ManageDeviceNotes)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Lock all membership edges, including those outside the requested scope.
	// Permission, membership and device locks survive until the audit commits.
	if _, err = tx.ExecContext(ctx, `LOCK TABLE site_agents IN SHARE MODE`); err != nil {
		return nil, err
	}
	lock := "FOR SHARE OF a,s"
	if replacement != nil {
		lock = "FOR UPDATE OF a FOR SHARE OF s"
	}
	var result DeviceNotes
	var notes sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT a.oid,COALESCE(NULLIF(a.nickname,''),a.hostname),s.tenant_sites,s.id,a.uem_notes_revision::text,
 CASE WHEN octet_length(COALESCE(a.notes,''))<=$4 THEN COALESCE(a.notes,'') END
 FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites s ON s.id=sa.site_id
 WHERE a.oid=$1 AND s.tenant_sites=$2 AND ($3::bigint=0 OR s.id=$3)
 AND a.agent_status IN ('Enabled','No contact','Disabled')
 AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1 `+lock,
		deviceID, scope.TenantID, scope.SiteID, MaxDeviceNotesBytes).Scan(&result.DeviceID, &result.DeviceName, &result.TenantID, &result.SiteID, &result.Revision, &notes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !notes.Valid || !ValidDeviceNotes(notes.String) {
		return nil, ErrDeviceNotesInvalid
	}
	result.Notes = notes.String
	action := "inventory.notes.read"
	if replacement != nil {
		if result.Revision != revision {
			return nil, ErrDeviceNotesConflict
		}
		if err = tx.QueryRowContext(ctx, `UPDATE agents SET notes=$2 WHERE oid=$1 RETURNING uem_notes_revision::text`, deviceID, *replacement).Scan(&result.Revision); err != nil {
			return nil, err
		}
		result.Notes = *replacement
		action = "inventory.notes.update"
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,$4,$5)`,
		result.TenantID, result.SiteID, actor, action, result.DeviceID+"/"+result.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &result, nil
}
