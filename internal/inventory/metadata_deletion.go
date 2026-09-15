package inventory

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type MetadataDeletion struct {
	ID, Actor            string
	Field                MetadataField
	ValueCount           int64
	CreatedAt, ExpiresAt time.Time
	CompletedAt          *time.Time
	sourceHash           []byte
}

func metadataDeletionImpact(ctx context.Context, tx *sql.Tx, field MetadataField) (int64, []byte, error) {
	h := sha256.New()
	if err := assignmentHashPart(h, []any{field.ID, field.TenantID, field.Revision}); err != nil {
		return 0, nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT m.id,m.agent_metadata,r.revision::text,COALESCE(s.tenant_sites,0),COALESCE(s.id,0),
 (SELECT count(*) FROM site_agents WHERE agent_id=m.agent_metadata),b.revision::text
 FROM metadata m LEFT JOIN uem_metadata_value_revisions r ON r.device_id=m.agent_metadata AND r.field_id=m.org_metadata_metadata
 LEFT JOIN uem_netbird_device_bindings b ON b.device_id=m.agent_metadata
 LEFT JOIN site_agents sa ON sa.agent_id=m.agent_metadata LEFT JOIN sites s ON s.id=sa.site_id
 WHERE m.org_metadata_metadata=$1 ORDER BY m.id`, field.ID)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	var count int64
	for rows.Next() {
		var id, tenant, site, memberships int64
		var device string
		var revision, binding sql.NullString
		if err = rows.Scan(&id, &device, &revision, &tenant, &site, &memberships, &binding); err != nil {
			return 0, nil, err
		}
		if memberships != 1 || tenant != int64(field.TenantID) || site <= 0 {
			return 0, nil, ErrMetadataUnsafeReferences
		}
		if !revision.Valid || !binding.Valid {
			return 0, nil, ErrMetadataInvalid
		}
		if err = assignmentHashPart(h, []any{id, device, site, revision.String, binding.String}); err != nil {
			return 0, nil, err
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return 0, nil, err
	}
	rows.Close()
	// Include tombstones as well as configured values: create/delete between a
	// review and its confirmation must invalidate a review of an empty field.
	revisions, err := tx.QueryContext(ctx, `SELECT device_id,revision::text FROM uem_metadata_value_revisions WHERE field_id=$1 AND changed ORDER BY device_id`, field.ID)
	if err != nil {
		return 0, nil, err
	}
	defer revisions.Close()
	for revisions.Next() {
		var device, revision string
		if err = revisions.Scan(&device, &revision); err != nil {
			return 0, nil, err
		}
		if err = assignmentHashPart(h, []any{"revision", device, revision}); err != nil {
			return 0, nil, err
		}
	}
	if err = revisions.Err(); err != nil {
		return 0, nil, err
	}
	return count, h.Sum(nil), nil
}

func ReviewMetadataDeletion(parent context.Context, db *sql.DB, permissions *access.Store, actor string, tenant, id int, revision string) (*MetadataDeletion, error) {
	if id <= 0 || !validMetadataUUID(revision) {
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
	if f.Revision != revision {
		return nil, ErrMetadataConflict
	}
	count, digest, err := metadataDeletionImpact(ctx, tx, f)
	if err != nil {
		return nil, err
	}
	r := &MetadataDeletion{Actor: actor, Field: f, ValueCount: count, sourceHash: digest}
	err = tx.QueryRowContext(ctx, `INSERT INTO uem_metadata_field_deletions(tenant_id,field_id,field_revision,actor,name,description,value_count,source_hash)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id::text,created_at,expires_at`, tenant, id, revision, actor, f.Name, f.Description, count, digest).Scan(&r.ID, &r.CreatedAt, &r.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if err = metadataAudit(ctx, tx, actor, scope, "inventory.metadata.field.delete_review", r.ID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

func MetadataDeletionReceipt(parent context.Context, db *sql.DB, permissions *access.Store, actor string, tenant, field int, id string, commit bool) (*MetadataDeletion, error) {
	if field <= 0 || !validMetadataUUID(id) {
		return nil, ErrMetadataInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	scope := access.Scope{TenantID: tenant}
	tx, err := metadataTransaction(ctx, db, permissions, actor, scope, commit)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r := &MetadataDeletion{}
	err = tx.QueryRowContext(ctx, `SELECT id::text,actor,tenant_id,field_id,field_revision::text,name,description,value_count,source_hash,created_at,expires_at,completed_at
 FROM uem_metadata_field_deletions WHERE id=$1 AND actor=$2 AND tenant_id=$3 AND field_id=$4 FOR UPDATE`, id, actor, tenant, field).
		Scan(&r.ID, &r.Actor, &r.Field.TenantID, &r.Field.ID, &r.Field.Revision, &r.Field.Name, &r.Field.Description, &r.ValueCount, &r.sourceHash, &r.CreatedAt, &r.ExpiresAt, &r.CompletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	action := "inventory.metadata.field.receipt"
	if commit && r.CompletedAt == nil {
		var valid bool
		if err = tx.QueryRowContext(ctx, `SELECT expires_at>clock_timestamp() FROM uem_metadata_field_deletions WHERE id=$1`, id).Scan(&valid); err != nil {
			return nil, err
		}
		if !valid {
			return nil, ErrMetadataConflict
		}
		f, e := metadataField(ctx, tx, tenant, field, true)
		if errors.Is(e, ErrNotFound) {
			return nil, ErrMetadataConflict
		}
		if e != nil {
			return nil, e
		}
		count, digest, e := metadataDeletionImpact(ctx, tx, f)
		if e != nil {
			return nil, e
		}
		if count != r.ValueCount || subtle.ConstantTimeCompare(digest, r.sourceHash) != 1 {
			return nil, ErrMetadataConflict
		}
		// The foreign-key cascade and tombstone revisions are inside this same
		// transaction, together with the immutable receipt and deletion audit.
		if _, err = tx.ExecContext(ctx, `DELETE FROM org_metadata WHERE id=$1 AND tenant_metadata=$2`, field, tenant); err != nil {
			return nil, err
		}
		if err = tx.QueryRowContext(ctx, `UPDATE uem_metadata_field_deletions SET completed_at=statement_timestamp() WHERE id=$1 AND expires_at>statement_timestamp() RETURNING completed_at`, id).Scan(&r.CompletedAt); errors.Is(err, sql.ErrNoRows) {
			return nil, ErrMetadataConflict
		} else if err != nil {
			return nil, err
		}
		action = "inventory.metadata.field.delete"
	}
	if err = metadataAudit(ctx, tx, actor, scope, action, r.ID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}
