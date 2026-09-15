package inventory

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-uem/openuem-console/internal/security/access"
)

const MaxMetadataValueBytes = 16 << 10

var ErrMetadataInvalid = errors.New("invalid metadata field, value or revision")
var ErrMetadataConflict = errors.New("metadata changed; review the current field and value")
var ErrMetadataNameUnavailable = errors.New("metadata field name is unavailable")
var ErrMetadataUnsafeReferences = errors.New("metadata field has values without unambiguous organization ownership")

type MetadataField struct {
	ID, TenantID                int
	Name, Description, Revision string
	Configured                  bool
}

type MetadataFieldPage struct {
	Fields []MetadataField
	Next   int
}

type MetadataDevice struct {
	ID, Name         string
	TenantID, SiteID int
}

type DeviceMetadataPage struct {
	Device MetadataDevice
	MetadataFieldPage
}

type MetadataValue struct {
	Device          MetadataDevice
	Field           MetadataField
	Revision, Value string
	Present         bool
}

func metadataFieldResource(f MetadataField) string { return strconv.Itoa(f.ID) + "/" + f.Revision }
func metadataValueResource(v *MetadataValue) string {
	digest := sha256.Sum256([]byte(v.Device.ID))
	return "sha256:" + hex.EncodeToString(digest[:]) + "/" + strconv.Itoa(v.Field.ID) + "/" + v.Revision
}

func validMetadataUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func validMetadataField(name, description string) bool {
	return strings.TrimSpace(name) != "" && validDetailText(name, 255, false) && validDetailText(description, 4096, true)
}

func validMetadataSearch(search string, after int) bool {
	return after >= 0 && validDetailText(search, 256, false)
}

func metadataTransaction(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, write bool) (*sql.Tx, error) {
	tx, err := beginGroupTransaction(ctx, db, permissions, actor, scope, access.ManageMetadata)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `LOCK TABLE site_agents,sites IN SHARE MODE`); err != nil {
		tx.Rollback()
		return nil, err
	}
	mode := "SHARE"
	if write {
		mode = "SHARE ROW EXCLUSIVE"
	}
	// Include absent values and older writers, not only the rows already visible.
	if _, err = tx.ExecContext(ctx, `LOCK TABLE metadata IN `+mode+` MODE`); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func metadataAudit(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope, action, resource string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,$4,$5)`, scope.TenantID, scope.SiteID, actor, action, resource)
	return err
}

func metadataField(ctx context.Context, tx *sql.Tx, tenant, id int, write bool) (MetadataField, error) {
	lock := "FOR SHARE"
	if write {
		lock = "FOR UPDATE"
	}
	var f MetadataField
	var name, description sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT id,tenant_metadata,uem_revision::text,
 CASE WHEN octet_length(name)<=255 THEN name END,
 CASE WHEN octet_length(COALESCE(description,''))<=4096 THEN COALESCE(description,'') END
 FROM org_metadata WHERE id=$1 AND tenant_metadata=$2 `+lock, id, tenant).Scan(&f.ID, &f.TenantID, &f.Revision, &name, &description)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	if err != nil {
		return f, err
	}
	f.Name, f.Description = name.String, description.String
	if !name.Valid || !description.Valid || !validMetadataField(f.Name, f.Description) {
		return f, ErrMetadataInvalid
	}
	return f, nil
}

func metadataSource(ctx context.Context, tx *sql.Tx, scope access.Scope, id string) (MetadataDevice, error) {
	var d MetadataDevice
	err := tx.QueryRowContext(ctx, `SELECT a.oid,left(COALESCE(NULLIF(a.nickname,''),NULLIF(a.hostname,''),a.oid),512),s.tenant_sites,s.id
 FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites s ON s.id=sa.site_id
 WHERE a.oid=$1 AND s.tenant_sites=$2 AND ($3::bigint=0 OR s.id=$3)
 AND a.agent_status IN ('Enabled','No contact','Disabled') AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1
 FOR SHARE OF a,s`, id, scope.TenantID, scope.SiteID).Scan(&d.ID, &d.Name, &d.TenantID, &d.SiteID)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return d, err
}

func metadataFields(ctx context.Context, tx *sql.Tx, tenant int, device, search string, after int) (MetadataFieldPage, error) {
	var page MetadataFieldPage
	pattern := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(search) + "%"
	rows, err := tx.QueryContext(ctx, `SELECT f.id,f.tenant_metadata,f.uem_revision::text,left(f.name,255),left(COALESCE(f.description,''),4096),
 EXISTS(SELECT 1 FROM metadata m WHERE m.org_metadata_metadata=f.id AND m.agent_metadata=$4)
 FROM org_metadata f WHERE f.tenant_metadata=$1 AND f.id>$2 AND (f.name ILIKE $3 OR f.description ILIKE $3)
 ORDER BY f.id LIMIT 26 FOR SHARE OF f`, tenant, after, pattern, device)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var f MetadataField
		if err = rows.Scan(&f.ID, &f.TenantID, &f.Revision, &f.Name, &f.Description, &f.Configured); err != nil {
			return page, err
		}
		page.Fields = append(page.Fields, f)
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	if len(page.Fields) > 25 {
		page.Fields = page.Fields[:25]
		page.Next = page.Fields[24].ID
	}
	return page, nil
}

func ListMetadataFields(parent context.Context, db *sql.DB, permissions *access.Store, actor string, tenant int, search string, after int) (*MetadataFieldPage, error) {
	if !validMetadataSearch(search, after) {
		return nil, ErrMetadataInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	scope := access.Scope{TenantID: tenant}
	tx, err := metadataTransaction(ctx, db, permissions, actor, scope, false)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	page, err := metadataFields(ctx, tx, tenant, "", search, after)
	if err != nil {
		return nil, err
	}
	if err = metadataAudit(ctx, tx, actor, scope, "inventory.metadata.fields.list", "fields"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &page, nil
}

func ReadMetadataField(parent context.Context, db *sql.DB, permissions *access.Store, actor string, tenant, id int) (*MetadataField, error) {
	if id <= 0 {
		return nil, ErrMetadataInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	scope := access.Scope{TenantID: tenant}
	tx, err := metadataTransaction(ctx, db, permissions, actor, scope, false)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	f, err := metadataField(ctx, tx, tenant, id, false)
	if err != nil {
		return nil, err
	}
	if err = metadataAudit(ctx, tx, actor, scope, "inventory.metadata.field.read", metadataFieldResource(f)); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &f, nil
}

func SaveMetadataField(parent context.Context, db *sql.DB, permissions *access.Store, actor string, tenant, id int, revision, name, description string) (*MetadataField, error) {
	if id < 0 || !validMetadataField(name, description) || id > 0 && !validMetadataUUID(revision) || id == 0 && revision != "" {
		return nil, ErrMetadataInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	scope := access.Scope{TenantID: tenant}
	tx, err := metadataTransaction(ctx, db, permissions, actor, scope, true)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	action := "inventory.metadata.field.create"
	if id == 0 {
		err = tx.QueryRowContext(ctx, `INSERT INTO org_metadata(name,description,tenant_metadata) VALUES($1,$2,$3) RETURNING id`, name, description, tenant).Scan(&id)
	} else {
		f, e := metadataField(ctx, tx, tenant, id, true)
		if e != nil {
			return nil, e
		}
		if f.Revision != revision {
			return nil, ErrMetadataConflict
		}
		_, err = tx.ExecContext(ctx, `UPDATE org_metadata SET name=$2,description=$3 WHERE id=$1`, id, name, description)
		action = "inventory.metadata.field.update"
	}
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return nil, ErrMetadataNameUnavailable
		}
		return nil, err
	}
	f, err := metadataField(ctx, tx, tenant, id, false)
	if err != nil {
		return nil, err
	}
	if err = metadataAudit(ctx, tx, actor, scope, action, metadataFieldResource(f)); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &f, nil
}

func ListDeviceMetadata(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, id, search string, after int) (*DeviceMetadataPage, error) {
	if !ValidReportDeviceID(id) {
		return nil, ErrNotFound
	}
	if !validMetadataSearch(search, after) {
		return nil, ErrMetadataInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := metadataTransaction(ctx, db, permissions, actor, scope, false)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := metadataSource(ctx, tx, scope, id)
	if err != nil {
		return nil, err
	}
	page, err := metadataFields(ctx, tx, d.TenantID, id, search, after)
	if err != nil {
		return nil, err
	}
	if err = metadataAudit(ctx, tx, actor, access.Scope{TenantID: d.TenantID, SiteID: d.SiteID}, "inventory.metadata.values.list", id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &DeviceMetadataPage{Device: d, MetadataFieldPage: page}, nil
}

func metadataValue(ctx context.Context, tx *sql.Tx, scope access.Scope, id string, field int) (*MetadataValue, error) {
	d, err := metadataSource(ctx, tx, scope, id)
	if err != nil {
		return nil, err
	}
	f, err := metadataField(ctx, tx, d.TenantID, field, false)
	if err != nil {
		return nil, err
	}
	// A read of an absent value issues a durable revision, so create/delete ABA
	// changes cannot make an old empty editor valid again.
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_metadata_value_revisions(device_id,field_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, field); err != nil {
		return nil, err
	}
	v := &MetadataValue{Device: d, Field: f}
	var value sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT r.revision::text,m.id IS NOT NULL,
 CASE WHEN m.id IS NULL THEN '' WHEN octet_length(m.value)<=$3 THEN m.value END
 FROM uem_metadata_value_revisions r LEFT JOIN metadata m ON m.agent_metadata=r.device_id AND m.org_metadata_metadata=r.field_id
 WHERE r.device_id=$1 AND r.field_id=$2 FOR SHARE OF r`, id, field, MaxMetadataValueBytes).Scan(&v.Revision, &v.Present, &value)
	if err != nil {
		return nil, err
	}
	if !value.Valid || !validDetailText(value.String, MaxMetadataValueBytes, true) {
		return nil, ErrMetadataInvalid
	}
	v.Value = value.String
	return v, nil
}

func ReadMetadataValue(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, id string, field int) (*MetadataValue, error) {
	if !ValidReportDeviceID(id) {
		return nil, ErrNotFound
	}
	if field <= 0 {
		return nil, ErrMetadataInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := metadataTransaction(ctx, db, permissions, actor, scope, false)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	v, err := metadataValue(ctx, tx, scope, id, field)
	if err != nil {
		return nil, err
	}
	if err = metadataAudit(ctx, tx, actor, access.Scope{TenantID: v.Device.TenantID, SiteID: v.Device.SiteID}, "inventory.metadata.value.read", metadataValueResource(v)); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return v, nil
}

func SaveMetadataValue(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, id string, field int, fieldRevision, revision, value string, clear bool) (*MetadataValue, error) {
	if !ValidReportDeviceID(id) {
		return nil, ErrNotFound
	}
	if field <= 0 || !validMetadataUUID(fieldRevision) || !validMetadataUUID(revision) || !validDetailText(value, MaxMetadataValueBytes, true) || clear && value != "" {
		return nil, ErrMetadataInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := metadataTransaction(ctx, db, permissions, actor, scope, true)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	v, err := metadataValue(ctx, tx, scope, id, field)
	if err != nil {
		return nil, err
	}
	if v.Field.Revision != fieldRevision || v.Revision != revision {
		return nil, ErrMetadataConflict
	}
	action := "inventory.metadata.value.update"
	if clear {
		_, err = tx.ExecContext(ctx, `DELETE FROM metadata WHERE agent_metadata=$1 AND org_metadata_metadata=$2`, id, field)
		action = "inventory.metadata.value.clear"
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO metadata(agent_metadata,org_metadata_metadata,value) VALUES($1,$2,$3) ON CONFLICT(org_metadata_metadata,agent_metadata) DO UPDATE SET value=excluded.value`, id, field, value)
	}
	if err != nil {
		return nil, err
	}
	v, err = metadataValue(ctx, tx, scope, id, field)
	if err != nil {
		return nil, err
	}
	if err = metadataAudit(ctx, tx, actor, access.Scope{TenantID: v.Device.TenantID, SiteID: v.Device.SiteID}, action, metadataValueResource(v)); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return v, nil
}
