package windows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrUpdateRing = errors.New("invalid native Windows update ring")
var ErrUpdateRingConflict = errors.New("native Windows update ring revision or request conflict")

// Each edit creates a revision; disabling a ring is also an explicit revision.
// Existing rollouts always retain their originally reviewed policy.
type UpdateRingRevision struct {
	RingID            string       `json:"-" xml:"-"`
	Scope             access.Scope `json:"-" xml:"-"`
	Revision          int64        `json:"-" xml:"-"`
	RequestKey        string       `json:"-" xml:"-"`
	CreatedBy         string       `json:"-" xml:"-"`
	CreatedByRevision int64        `json:"-" xml:"-"`
	Enabled           bool         `json:"-" xml:"-"`
	CreatedAt         time.Time    `json:"-" xml:"-"`
	Name              string       `json:"-" xml:"-"`
	Policy            UpdatePolicy `json:"-" xml:"-"`
}

type updateStoredRing struct {
	UpdateRingRevision
	encrypted []byte
}

type updateRingIntent struct {
	Version int
	Name    string
	Policy  UpdatePolicy
}

func (UpdateRingRevision) String() string     { return "[protected Windows update ring revision]" }
func (v UpdateRingRevision) GoString() string { return v.String() }
func (updateRingIntent) String() string       { return "[protected Windows update ring intent]" }
func (v updateRingIntent) GoString() string   { return v.String() }

const updateRingColumns = `ring_id,tenant_id,site_id,revision,request_key,created_by,created_by_revision,enabled,created_at,encrypted_intent`

func scanUpdateRing(row cspScanner) (*updateStoredRing, error) {
	r := &updateStoredRing{}
	err := row.Scan(&r.RingID, &r.Scope.TenantID, &r.Scope.SiteID, &r.Revision, &r.RequestKey, &r.CreatedBy, &r.CreatedByRevision, &r.Enabled, &r.CreatedAt, &r.encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func updateRingPurpose(r *updateStoredRing) string {
	return fmt.Sprintf("openuem/windows/update-ring/v1/%s/%d/%d/%d/%s/%x/%d/%t/%s", r.RingID, r.Scope.TenantID, r.Scope.SiteID, r.Revision, r.RequestKey, sha256.Sum256([]byte(r.CreatedBy)), r.CreatedByRevision, r.Enabled, r.CreatedAt.UTC().Format(time.RFC3339Nano))
}

func (s *Store) openUpdateRing(r *updateStoredRing) error {
	plain, err := s.secrets.openBounded(r.encrypted, updateRingPurpose(r), 8192)
	if err != nil {
		return err
	}
	defer clear(plain)
	var intent updateRingIntent
	if decodeSyncMLProtectedJSON(plain, &intent) != nil || intent.Version != 1 || !validEnrollmentUsername(intent.Name) || len(intent.Name) > 128 || intent.Policy.Validate() != nil {
		return ErrAuthoritySecret
	}
	r.Name, r.Policy = intent.Name, intent.Policy
	return nil
}

func (s *Store) authorizeUpdateRing(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope) error {
	if !validEnrollmentUsername(actor) || len(actor) > 255 || scope.TenantID < 1 || scope.SiteID < 1 {
		return ErrUpdateRing
	}
	if err := s.permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageUpdates, scope); err != nil {
		return err
	}
	return lockEnrollmentScope(ctx, tx, scope)
}

func (s *Store) updateRingRevision(ctx context.Context, tx *sql.Tx, scope access.Scope, id string, revision int64) (*updateStoredRing, error) {
	r, err := scanUpdateRing(tx.QueryRowContext(ctx, `SELECT `+updateRingColumns+` FROM mdm_windows_update_ring_revisions WHERE ring_id=$1 AND revision=$2 AND tenant_id=$3 AND site_id=$4 FOR SHARE`, id, revision, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, err
	}
	if err := s.openUpdateRing(r); err != nil {
		return nil, err
	}
	return r, nil
}

func auditUpdateRing(ctx context.Context, tx *sql.Tx, r *updateStoredRing, actor, action, rollout string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_update_ring_audit(ring_id,ring_revision,tenant_id,site_id,actor,action,rollout_id) VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,'')::uuid)`, r.RingID, r.Revision, r.Scope.TenantID, r.Scope.SiteID, actor, action, rollout)
	return err
}

// SaveUpdateRing requires a stable ring UUID, a new request UUID per edit and the
// revision the caller reviewed (zero when creating). Retries never add revisions.
func (s *Store) SaveUpdateRing(ctx context.Context, actor string, scope access.Scope, ringID, requestKey string, expectedRevision int64, name string, policy UpdatePolicy, enabled bool) (*UpdateRingRevision, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !canonicalInvitationID(ringID) || !canonicalInvitationID(requestKey) || expectedRevision < 0 || expectedRevision >= 1000000 || !validEnrollmentUsername(name) || len(name) > 128 || policy.Validate() != nil {
		return nil, ErrUpdateRing
	}
	plain, err := json.Marshal(updateRingIntent{Version: 1, Name: name, Policy: policy})
	if err != nil {
		return nil, ErrUpdateRing
	}
	defer clear(plain)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeUpdateRing(ctx, tx, actor, scope); err != nil {
		return nil, err
	}
	var permissionRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM uem_access_revisions WHERE user_id=$1`, actor).Scan(&permissionRevision); err != nil {
		return nil, err
	}
	created := false
	if expectedRevision == 0 {
		result, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_update_rings(id,tenant_id,site_id,current_revision) VALUES($1,$2,$3,1) ON CONFLICT(id) DO NOTHING`, ringID, scope.TenantID, scope.SiteID)
		if err != nil {
			return nil, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return nil, err
		}
		created = n == 1
	}
	var current int64
	if err := tx.QueryRowContext(ctx, `SELECT current_revision FROM mdm_windows_update_rings WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR UPDATE`, ringID, scope.TenantID, scope.SiteID).Scan(&current); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	previous, err := scanUpdateRing(tx.QueryRowContext(ctx, `SELECT `+updateRingColumns+` FROM mdm_windows_update_ring_revisions WHERE ring_id=$1 AND request_key=$2`, ringID, requestKey))
	if err == nil {
		if err := s.openUpdateRing(previous); err != nil {
			return nil, err
		}
		old, err := json.Marshal(updateRingIntent{Version: 1, Name: previous.Name, Policy: previous.Policy})
		if err != nil {
			return nil, ErrAuthoritySecret
		}
		defer clear(old)
		if previous.Scope != scope || previous.Revision != expectedRevision+1 || previous.CreatedBy != actor || previous.CreatedByRevision != permissionRevision || previous.Enabled != enabled || !bytes.Equal(plain, old) {
			return nil, ErrUpdateRingConflict
		}
		if err := auditUpdateRing(ctx, tx, previous, actor, "ring.replayed", ""); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &previous.UpdateRingRevision, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if !created && current != expectedRevision {
		return nil, ErrUpdateRingConflict
	}
	r := &updateStoredRing{UpdateRingRevision: UpdateRingRevision{RingID: ringID, Scope: scope, Revision: expectedRevision + 1, RequestKey: requestKey, CreatedBy: actor, CreatedByRevision: permissionRevision, Enabled: enabled, Name: name, Policy: policy}}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&r.CreatedAt); err != nil {
		return nil, err
	}
	r.encrypted, err = s.secrets.sealBounded(plain, updateRingPurpose(r), 8192)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_update_ring_revisions(ring_id,tenant_id,site_id,revision,request_key,created_by,created_by_revision,enabled,created_at,encrypted_intent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, r.RingID, scope.TenantID, scope.SiteID, r.Revision, requestKey, actor, permissionRevision, enabled, r.CreatedAt, r.encrypted); err != nil {
		return nil, err
	}
	if !created {
		if _, err := tx.ExecContext(ctx, `UPDATE mdm_windows_update_rings SET current_revision=$2 WHERE id=$1`, ringID, r.Revision); err != nil {
			return nil, err
		}
	}
	if err := auditUpdateRing(ctx, tx, r, actor, "ring.saved", ""); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &r.UpdateRingRevision, nil
}

// UpdateRingRevisions returns newest-first history; before=0 starts at the head.
// Values become visible only after the scoped read audit commits.
func (s *Store) UpdateRingRevisions(ctx context.Context, actor string, scope access.Scope, ringID string, before int64, limit int) ([]UpdateRingRevision, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !canonicalInvitationID(ringID) || before < 0 || before > 1000001 || limit < 1 || limit > 100 {
		return nil, ErrUpdateRing
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeUpdateRing(ctx, tx, actor, scope); err != nil {
		return nil, err
	}
	var current int64
	if err := tx.QueryRowContext(ctx, `SELECT current_revision FROM mdm_windows_update_rings WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR SHARE`, ringID, scope.TenantID, scope.SiteID).Scan(&current); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+updateRingColumns+` FROM mdm_windows_update_ring_revisions WHERE ring_id=$1 AND tenant_id=$2 AND site_id=$3 AND ($4::bigint=0 OR revision<$4) ORDER BY revision DESC LIMIT $5`, ringID, scope.TenantID, scope.SiteID, before, limit)
	if err != nil {
		return nil, err
	}
	stored := []*updateStoredRing{}
	for rows.Next() {
		r, err := scanUpdateRing(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		stored = append(stored, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := []UpdateRingRevision{}
	for _, r := range stored {
		if err := s.openUpdateRing(r); err != nil {
			return nil, err
		}
		if err := auditUpdateRing(ctx, tx, r, actor, "ring.read", ""); err != nil {
			return nil, err
		}
		result = append(result, r.UpdateRingRevision)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// UpdateRings lists current revisions, including disabled rings, within one site.
func (s *Store) UpdateRings(ctx context.Context, actor string, scope access.Scope, offset, limit int) ([]UpdateRingRevision, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if offset < 0 || offset > 100000 || limit < 1 || limit > 100 {
		return nil, ErrUpdateRing
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeUpdateRing(ctx, tx, actor, scope); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+updateRingColumns+` FROM mdm_windows_update_ring_revisions r WHERE tenant_id=$1 AND site_id=$2 AND EXISTS(SELECT 1 FROM mdm_windows_update_rings h WHERE h.id=r.ring_id AND h.current_revision=r.revision AND h.tenant_id=r.tenant_id AND h.site_id=r.site_id) ORDER BY created_at DESC,ring_id LIMIT $3 OFFSET $4`, scope.TenantID, scope.SiteID, limit, offset)
	if err != nil {
		return nil, err
	}
	stored := []*updateStoredRing{}
	for rows.Next() {
		r, err := scanUpdateRing(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		stored = append(stored, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := []UpdateRingRevision{}
	for _, r := range stored {
		if err := s.openUpdateRing(r); err != nil {
			return nil, err
		}
		if err := auditUpdateRing(ctx, tx, r, actor, "ring.read", ""); err != nil {
			return nil, err
		}
		result = append(result, r.UpdateRingRevision)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
