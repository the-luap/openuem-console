package inventory

import (
	"context"
	"database/sql"
	"errors"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/security/access"
)

const MaxDeviceNicknameBytes = 255
const MaxDeviceDescriptionBytes = 4096

var ErrDeviceDetailsInvalid = errors.New("invalid device details or revision")
var ErrDeviceDetailsConflict = errors.New("device details changed; review the saved values before saving")

type DeviceDetailValues struct {
	Nickname, Description, EndpointType string
}

type DeviceDetails struct {
	DeviceID, Hostname, Revision string
	TenantID, SiteID             int
	Values                       DeviceDetailValues
}

func validDetailText(value string, max int, multiline bool) bool {
	if len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) && (!multiline || r != '\n' && r != '\r' && r != '\t') {
			return false
		}
	}
	return true
}

func ValidDeviceDetailValues(values DeviceDetailValues) bool {
	return validDetailText(values.Nickname, MaxDeviceNicknameBytes, false) &&
		validDetailText(values.Description, MaxDeviceDescriptionBytes, true) &&
		agent.EndpointTypeValidator(agent.EndpointType(values.EndpointType)) == nil
}

func ReadDeviceDetails(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, deviceID string) (*DeviceDetails, error) {
	return deviceDetails(ctx, db, permissions, actor, scope, deviceID, "", nil)
}

func UpdateDeviceDetails(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, deviceID, revision string, values DeviceDetailValues) (*DeviceDetails, error) {
	id, err := uuid.Parse(revision)
	if err != nil || id == uuid.Nil || id.String() != revision || !ValidDeviceDetailValues(values) {
		return nil, ErrDeviceDetailsInvalid
	}
	return deviceDetails(ctx, db, permissions, actor, scope, deviceID, revision, &values)
}

func deviceDetails(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, deviceID, revision string, replacement *DeviceDetailValues) (*DeviceDetails, error) {
	if !ValidReportDeviceID(deviceID) {
		return nil, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginGroupTransaction(ctx, db, permissions, actor, scope, access.ManageDeviceDetails)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Freeze the entire membership set, including foreign edges and insert gaps.
	if _, err = tx.ExecContext(ctx, `LOCK TABLE site_agents IN SHARE MODE`); err != nil {
		return nil, err
	}
	lock := "FOR SHARE OF a,s"
	if replacement != nil {
		lock = "FOR UPDATE OF a FOR SHARE OF s"
	}
	var out DeviceDetails
	var nickname, description sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT a.oid,left(COALESCE(a.hostname,''),512),a.uem_details_revision::text,s.tenant_sites,s.id,
 CASE WHEN octet_length(COALESCE(a.nickname,''))<=$4 THEN COALESCE(a.nickname,'') END,
 CASE WHEN octet_length(COALESCE(a.description,''))<=$5 THEN COALESCE(a.description,'') END,a.endpoint_type
 FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites s ON s.id=sa.site_id
 WHERE a.oid=$1 AND s.tenant_sites=$2 AND ($3::bigint=0 OR s.id=$3)
 AND a.agent_status IN ('Enabled','No contact','Disabled')
 AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1 `+lock, deviceID, scope.TenantID, scope.SiteID, MaxDeviceNicknameBytes, MaxDeviceDescriptionBytes).
		Scan(&out.DeviceID, &out.Hostname, &out.Revision, &out.TenantID, &out.SiteID, &nickname, &description, &out.Values.EndpointType)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out.Values.Nickname, out.Values.Description = nickname.String, description.String
	if !nickname.Valid || !description.Valid || !ValidDeviceDetailValues(out.Values) {
		return nil, ErrDeviceDetailsInvalid
	}
	action := "inventory.details.read"
	if replacement != nil {
		if revision != out.Revision {
			return nil, ErrDeviceDetailsConflict
		}
		if err = tx.QueryRowContext(ctx, `UPDATE agents SET nickname=$2,description=$3,endpoint_type=$4 WHERE oid=$1 RETURNING uem_details_revision::text`, deviceID, replacement.Nickname, replacement.Description, replacement.EndpointType).Scan(&out.Revision); err != nil {
			return nil, err
		}
		out.Values = *replacement
		action = "inventory.details.update"
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,$4,$5)`, out.TenantID, out.SiteID, actor, action, out.DeviceID+"/"+out.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &out, nil
}
