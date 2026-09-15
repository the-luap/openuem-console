package inventory

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"hash"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var (
	ErrAssignmentInvalid  = errors.New("invalid device assignment")
	ErrAssignmentChanged  = errors.New("device assignment review changed or expired")
	ErrAssignmentIdentity = errors.New("individual device identities require enrollment in the destination scope")
)

type AssignmentLocation struct {
	TenantID, SiteID   int
	Organization, Site string
}

type DeviceAssignmentReview struct {
	ID, DeviceID, Actor, DeviceName string
	Source, Target                  AssignmentLocation
	TagCount, MetadataCount         int64
	CreatedAt, ExpiresAt            time.Time
	CompletedAt                     *time.Time
	sourceHash                      []byte
}

type DeviceAssignmentChoices struct {
	DeviceID, DeviceName string
	Source               AssignmentLocation
	IndividualIdentity   bool
	Locations            []AssignmentLocation
	Next                 int
}

func assignmentTransaction(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, write bool) (*sql.Tx, bool, error) {
	tx, err := beginGroupTransaction(ctx, db, permissions, actor, scope, access.ManageDeviceAssignments)
	if err != nil {
		return nil, false, err
	}
	global := false
	err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageDeviceAssignments, access.Scope{})
	if err == nil {
		global = true
	} else if !errors.Is(err, access.ErrDenied) {
		tx.Rollback()
		return nil, false, err
	}
	mode := "SHARE"
	if write {
		mode = "SHARE ROW EXCLUSIVE"
	}
	// Freeze the whole edge sets: checking only visible edges misses foreign
	// associations and permits concurrent inserts to escape the reviewed impact.
	if _, err = tx.ExecContext(ctx, `LOCK TABLE site_agents,agent_tags,metadata,org_metadata IN `+mode+` MODE`); err != nil {
		tx.Rollback()
		return nil, false, err
	}
	if _, err = tx.ExecContext(ctx, `LOCK TABLE tags IN SHARE MODE`); err != nil {
		tx.Rollback()
		return nil, false, err
	}
	return tx, global, nil
}

func assignmentSource(ctx context.Context, tx *sql.Tx, scope access.Scope, device string, write bool) (*DeviceAssignmentReview, error) {
	lock := "FOR SHARE OF a,s,t"
	if write {
		lock = "FOR UPDATE OF a FOR SHARE OF s,t"
	}
	r := &DeviceAssignmentReview{DeviceID: device}
	err := tx.QueryRowContext(ctx, `SELECT left(COALESCE(NULLIF(a.nickname,''),NULLIF(a.hostname,''),a.oid),512),t.id,s.id,left(t.description,256),left(s.description,256)
 FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites s ON s.id=sa.site_id JOIN tenants t ON t.id=s.tenant_sites
 WHERE a.oid=$1 AND t.id=$2 AND ($3::bigint=0 OR s.id=$3) AND a.agent_status IN ('Enabled','No contact','Disabled')
 AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1 `+lock, device, scope.TenantID, scope.SiteID).
		Scan(&r.DeviceName, &r.Source.TenantID, &r.Source.SiteID, &r.Source.Organization, &r.Source.Site)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}

func assignmentIndividualIdentity(ctx context.Context, tx *sql.Tx, device string) (bool, error) {
	var present bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('uem_agent_identities') IS NOT NULL`).Scan(&present); err != nil || !present {
		return false, err
	}
	// Retained/revoked identities still own their historical certificate scope.
	// A concurrent claim cannot create an identity between this check and commit.
	if _, err := tx.ExecContext(ctx, `LOCK TABLE uem_agent_identities IN SHARE MODE`); err != nil {
		return false, err
	}
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_identities WHERE id::text=$1)`, device).Scan(&present)
	return present, err
}

func assignmentLocation(ctx context.Context, tx *sql.Tx, siteID int) (AssignmentLocation, error) {
	var loc AssignmentLocation
	err := tx.QueryRowContext(ctx, `SELECT t.id,s.id,left(t.description,256),left(s.description,256) FROM sites s JOIN tenants t ON t.id=s.tenant_sites WHERE s.id=$1 FOR SHARE OF s,t`, siteID).Scan(&loc.TenantID, &loc.SiteID, &loc.Organization, &loc.Site)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return loc, err
}

func assignmentHashPart(h hash.Hash, v any) error { return json.NewEncoder(h).Encode(v) }

func assignmentFingerprint(ctx context.Context, tx *sql.Tx, r *DeviceAssignmentReview) ([]byte, error) {
	h := sha256.New()
	if err := assignmentHashPart(h, []any{r.DeviceID, r.DeviceName, r.Source, r.Target}); err != nil {
		return nil, err
	}
	var status, platform, notesRevision, detailsRevision, binding string
	if err := tx.QueryRowContext(ctx, `SELECT revision::text FROM uem_netbird_device_bindings WHERE device_id=$1 FOR SHARE`, r.DeviceID).Scan(&binding); err != nil {
		return nil, err
	}
	err := tx.QueryRowContext(ctx, `SELECT a.agent_status,a.os,a.uem_notes_revision::text,a.uem_details_revision::text,COALESCE(b.revision::text,'') FROM agents a LEFT JOIN uem_netbird_device_bindings b ON b.device_id=a.oid WHERE a.oid=$1`, r.DeviceID).Scan(&status, &platform, &notesRevision, &detailsRevision, &binding)
	if err != nil {
		return nil, err
	}
	if err = assignmentHashPart(h, []string{status, platform, notesRevision, detailsRevision, binding}); err != nil {
		return nil, err
	}
	// Stream fixed-size digests, never metadata contents or unbounded aggregates.
	rows, err := tx.QueryContext(ctx, `SELECT at.tag_id,t.uem_revision::text FROM agent_tags at JOIN tags t ON t.id=at.tag_id WHERE at.agent_id=$1 ORDER BY at.tag_id`, r.DeviceID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var revision string
		if err = rows.Scan(&id, &revision); err != nil {
			rows.Close()
			return nil, err
		}
		r.TagCount++
		if err = assignmentHashPart(h, []any{"tag", id, revision}); err != nil {
			rows.Close()
			return nil, err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT m.id,m.org_metadata_metadata,sha256(convert_to(m.value,'UTF8')),r.revision::text,f.uem_revision::text FROM metadata m LEFT JOIN uem_metadata_value_revisions r ON r.device_id=m.agent_metadata AND r.field_id=m.org_metadata_metadata LEFT JOIN org_metadata f ON f.id=m.org_metadata_metadata WHERE m.agent_metadata=$1 ORDER BY m.id`, r.DeviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var org sql.NullInt64
		var valueHash []byte
		var valueRevision, fieldRevision sql.NullString
		if err = rows.Scan(&id, &org, &valueHash, &valueRevision, &fieldRevision); err != nil {
			return nil, err
		}
		if !valueRevision.Valid || !fieldRevision.Valid {
			return nil, ErrAssignmentChanged
		}
		r.MetadataCount++
		if err = assignmentHashPart(h, []any{"metadata", id, org, valueHash, valueRevision.String, fieldRevision.String}); err != nil {
			return nil, err
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func ReadDeviceAssignmentChoices(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, device, search string, after int) (*DeviceAssignmentChoices, error) {
	if !ValidReportDeviceID(device) || after < 0 || len(search) > 256 || !utf8.ValidString(search) || strings.IndexFunc(search, unicode.IsControl) >= 0 {
		return nil, ErrAssignmentInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, global, err := assignmentTransaction(ctx, db, permissions, actor, scope, false)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	source, err := assignmentSource(ctx, tx, scope, device, false)
	if err != nil {
		return nil, err
	}
	individual, err := assignmentIndividualIdentity(ctx, tx, device)
	if err != nil {
		return nil, err
	}
	out := &DeviceAssignmentChoices{DeviceID: device, DeviceName: source.DeviceName, Source: source.Source, IndividualIdentity: individual}
	if !individual {
		pattern := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(search) + "%"
		rows, err := tx.QueryContext(ctx, `SELECT t.id,s.id,left(t.description,256),left(s.description,256) FROM sites s JOIN tenants t ON t.id=s.tenant_sites
 WHERE ($1::boolean OR t.id=$2) AND s.id<>$3 AND s.id>$4 AND (t.description ILIKE $5 OR s.description ILIKE $5 OR s.id::text ILIKE $5) ORDER BY s.id LIMIT 51`, global, scope.TenantID, source.Source.SiteID, after, pattern)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var loc AssignmentLocation
			if err = rows.Scan(&loc.TenantID, &loc.SiteID, &loc.Organization, &loc.Site); err != nil {
				rows.Close()
				return nil, err
			}
			out.Locations = append(out.Locations, loc)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if len(out.Locations) > 50 {
			out.Locations = out.Locations[:50]
			out.Next = out.Locations[49].SiteID
		}
	}
	if err = assignmentAudit(ctx, tx, actor, source.Source, "inventory.assignment.choices", device); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func ReviewDeviceAssignment(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, device string, targetSite int) (*DeviceAssignmentReview, error) {
	if !ValidReportDeviceID(device) || targetSite <= 0 {
		return nil, ErrAssignmentInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, global, err := assignmentTransaction(ctx, db, permissions, actor, scope, false)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := assignmentSource(ctx, tx, scope, device, false)
	if err != nil {
		return nil, err
	}
	if present, err := assignmentIndividualIdentity(ctx, tx, device); err != nil {
		return nil, err
	} else if present {
		return nil, ErrAssignmentIdentity
	}
	r.Target, err = assignmentLocation(ctx, tx, targetSite)
	if err != nil {
		return nil, err
	}
	if r.Target.SiteID == r.Source.SiteID {
		return nil, ErrAssignmentInvalid
	}
	if !global && r.Target.TenantID != r.Source.TenantID {
		return nil, access.ErrDenied
	}
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageDeviceAssignments, access.Scope{TenantID: r.Target.TenantID, SiteID: r.Target.SiteID}); err != nil {
		return nil, err
	}
	r.Actor = actor
	r.sourceHash, err = assignmentFingerprint(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO uem_device_assignment_reviews(device_id,actor,source_tenant,source_site,target_tenant,target_site,device_name,source_organization,source_location,target_organization,target_location,tag_count,metadata_count,source_hash)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id::text,created_at,expires_at`, device, actor, r.Source.TenantID, r.Source.SiteID, r.Target.TenantID, r.Target.SiteID, r.DeviceName, r.Source.Organization, r.Source.Site, r.Target.Organization, r.Target.Site, r.TagCount, r.MetadataCount, r.sourceHash).Scan(&r.ID, &r.CreatedAt, &r.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if err = assignmentAudit(ctx, tx, actor, r.Source, "inventory.assignment.review", r.ID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

func assignmentAudit(ctx context.Context, tx *sql.Tx, actor string, loc AssignmentLocation, action, resource string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,$4,$5)`, loc.TenantID, loc.SiteID, actor, action, resource)
	return err
}

const assignmentReviewColumns = `id::text,device_id,actor,source_tenant,source_site,target_tenant,target_site,device_name,source_organization,source_location,target_organization,target_location,tag_count,metadata_count,source_hash,created_at,expires_at,completed_at`

func readAssignmentReview(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope, device, id string) (*DeviceAssignmentReview, error) {
	r := &DeviceAssignmentReview{}
	err := tx.QueryRowContext(ctx, `SELECT `+assignmentReviewColumns+` FROM uem_device_assignment_reviews WHERE id=$1 AND device_id=$2 AND actor=$3 AND source_tenant=$4 AND ($5::bigint=0 OR source_site=$5) FOR UPDATE`, id, device, actor, scope.TenantID, scope.SiteID).
		Scan(&r.ID, &r.DeviceID, &r.Actor, &r.Source.TenantID, &r.Source.SiteID, &r.Target.TenantID, &r.Target.SiteID, &r.DeviceName, &r.Source.Organization, &r.Source.Site, &r.Target.Organization, &r.Target.Site, &r.TagCount, &r.MetadataCount, &r.sourceHash, &r.CreatedAt, &r.ExpiresAt, &r.CompletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}

func DeviceAssignmentReceipt(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, device, id string, commit bool) (*DeviceAssignmentReview, error) {
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil || parsed.String() != id || !ValidReportDeviceID(device) {
		return nil, ErrAssignmentInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, global, err := assignmentTransaction(ctx, db, permissions, actor, scope, commit)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := readAssignmentReview(ctx, tx, actor, scope, device, id)
	if err != nil {
		return nil, err
	}
	if !global && r.Target.TenantID != r.Source.TenantID {
		return nil, access.ErrDenied
	}
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageDeviceAssignments, access.Scope{TenantID: r.Target.TenantID, SiteID: r.Target.SiteID}); err != nil {
		return nil, err
	}
	if !commit || r.CompletedAt != nil {
		if err = assignmentAudit(ctx, tx, actor, r.Source, "inventory.assignment.read", r.ID); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return r, nil
	}
	var valid bool
	if err = tx.QueryRowContext(ctx, `SELECT expires_at>clock_timestamp() FROM uem_device_assignment_reviews WHERE id=$1`, id).Scan(&valid); err != nil {
		return nil, err
	}
	if !valid {
		return nil, ErrAssignmentChanged
	}
	current, err := assignmentSource(ctx, tx, access.Scope{TenantID: r.Source.TenantID, SiteID: r.Source.SiteID}, device, true)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrAssignmentChanged
	}
	if err != nil {
		return nil, err
	}
	if present, err := assignmentIndividualIdentity(ctx, tx, device); err != nil {
		return nil, err
	} else if present {
		return nil, ErrAssignmentIdentity
	}
	current.Target, err = assignmentLocation(ctx, tx, r.Target.SiteID)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrAssignmentChanged
	}
	if err != nil {
		return nil, err
	}
	fingerprint, err := assignmentFingerprint(ctx, tx, current)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(fingerprint, r.sourceHash) != 1 {
		return nil, ErrAssignmentChanged
	}
	if r.Source.TenantID != r.Target.TenantID {
		if _, err = tx.ExecContext(ctx, `DELETE FROM metadata WHERE agent_metadata=$1`, device); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM agent_tags WHERE agent_id=$1`, device); err != nil {
			return nil, err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM site_agents WHERE agent_id=$1 AND site_id=$2`, device, r.Source.SiteID); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO site_agents(agent_id,site_id) VALUES($1,$2)`, device, r.Target.SiteID); err != nil {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, `UPDATE uem_device_assignment_reviews SET completed_at=statement_timestamp() WHERE id=$1 AND expires_at>statement_timestamp() RETURNING completed_at`, id).Scan(&r.CompletedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAssignmentChanged
		}
		return nil, err
	}
	for _, event := range []struct {
		loc    AssignmentLocation
		action string
	}{{r.Source, "inventory.assignment.depart"}, {r.Target, "inventory.assignment.arrive"}} {
		if err = assignmentAudit(ctx, tx, actor, event.loc, event.action, r.ID); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

func AssignmentLocationID(loc AssignmentLocation) string {
	return strconv.Itoa(loc.TenantID) + "/" + strconv.Itoa(loc.SiteID)
}
