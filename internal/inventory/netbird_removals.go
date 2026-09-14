package inventory

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// NetbirdRemovalStore retains exact reviewed native state. Request admission is
// separate from command delivery; no connection or installation executor can
// consume these requests. Public records contain only source-free evidence.
type NetbirdRemovalStore struct {
	db          *sql.DB
	permissions *access.Store
	individual  bool
	control     NetbirdOperationControl
	execute     NetbirdRemovalExecutor
}

func NewNetbirdRemovalStore(db *sql.DB, permissions *access.Store, individual bool, control NetbirdOperationControl) (*NetbirdRemovalStore, error) {
	if db == nil || permissions == nil || control == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	return &NetbirdRemovalStore{db: db, permissions: permissions, individual: individual, control: control}, nil
}

type NetbirdRemovalReview struct {
	Target                     ManualTarget
	Descriptor                 packageapi.Removal
	DescriptorDigest, Revision string
	Journal                    netbirdcommand.State
	Absent                     bool
}

type NetbirdRemoval struct {
	ID, DeviceID, Actor, Revision, JournalRevision, DescriptorDigest string
	Scope                                                            access.Scope
	Descriptor                                                       packageapi.Removal
	RequestedAt, ExpiresAt                                           time.Time
	CancellationID, CancelledBy                                      string
	CancelledAt                                                      *time.Time
	CompletedAt                                                      *time.Time
	ReleasedAt                                                       *time.Time
	ReleasedBy, ResolutionID                                         string
}

type removalSource struct {
	review            NetbirdRemovalReview
	identity          netbirdcommand.Identity
	identityExpiresAt time.Time
}

func (removalSource) String() string               { return "NetBird removal source (private data redacted)" }
func (s removalSource) GoString() string           { return s.String() }
func (removalSource) MarshalJSON() ([]byte, error) { return nil, ErrNetbirdOperationInvalid }

func (s *NetbirdRemovalStore) begin(ctx context.Context, actor string, scope access.Scope, capability access.Capability) (*sql.Tx, error) {
	if ctx == nil || ctx.Err() != nil || scope.TenantID <= 0 || scope.SiteID <= 0 {
		return nil, ErrNetbirdOperationInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err = s.permissions.AuthorizeTransaction(ctx, tx, actor, capability, scope); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func (s *NetbirdRemovalStore) source(ctx context.Context, tx *sql.Tx, scope access.Scope, device string) (*removalSource, error) {
	if !s.individual {
		return nil, ErrNetbirdOperationNotReady
	}
	if !canonicalRequestID(device) {
		return nil, ErrNetbirdOperationInvalid
	}
	manual := &ManualExecutionStore{db: s.db, permissions: s.permissions, individual: true}
	target, err := manual.target(ctx, tx, scope, device)
	if err != nil {
		return nil, err
	}
	if target.Platform != "macos" && target.Platform != "linux" {
		return nil, ErrManualUnsupported
	}
	r := &removalSource{review: NetbirdRemovalReview{Target: target}}
	var platform, architecture, broker, generation string
	var consumer int64
	err = tx.QueryRowContext(ctx, `SELECT i.platform,i.architecture,i.certificate_hash,i.broker_key,q.revision,i.certificate_expires_at FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id WHERE i.id=$1 AND i.tenant_id=$2 AND i.site_id=$3 FOR SHARE OF i,q`, device, scope.TenantID, scope.SiteID).Scan(&platform, &architecture, &r.identity.CertificateHash, &broker, &consumer, &r.identityExpiresAt)
	if err != nil {
		return nil, err
	}
	r.identity.DeviceID, r.identity.TenantID, r.identity.SiteID, r.identity.Individual = device, int64(scope.TenantID), int64(scope.SiteID), true
	if !r.identity.Valid() || target.Platform != platform || len(broker) > 256 {
		return nil, ErrNetbirdOperationChanged
	}
	// Match report-writer lock ordering, even when periodic client inventory is absent.
	var ignored bool
	err = tx.QueryRowContext(ctx, `SELECT true FROM netbirds WHERE agent_netbird=$1 FOR SHARE`, device).Scan(&ignored)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT revision::text FROM uem_netbird_device_bindings WHERE device_id=$1 FOR SHARE`, device).Scan(&generation); err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	expires := at.Add(netbirdcommand.RemovalInspectionLifetime)
	if r.identityExpiresAt.Before(expires) {
		expires = r.identityExpiresAt
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	query := netbirdcommand.ControlRequest{Version: netbirdcommand.RemovalInspectionVersion, Identity: r.identity, RequestID: uuid.NewString(), Kind: "removal-state", IssuedAt: at, ExpiresAt: expires}
	if !query.Executable(r.identity, at) {
		return nil, ErrNetbirdOperationNotReady
	}
	probe, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	response, err := s.control(probe, query)
	if err != nil || response == nil || probe.Err() != nil || !response.Matches(query) || response.Outcome != "ok" && response.Outcome != "absent" || response.State.Status != "ready" {
		return nil, ErrNetbirdOperationNotReady
	}
	r.review.Journal, r.review.Absent = response.State, response.Outcome == "absent"
	if !r.review.Absent {
		d := response.Removal
		if !d.Valid() || d.Platform != platform || d.Architecture != architecture {
			return nil, ErrNetbirdOperationChanged
		}
		r.review.Descriptor = d
		r.review.DescriptorDigest, err = d.Digest()
		if err != nil {
			return nil, ErrNetbirdOperationChanged
		}
	}
	data, err := json.Marshal(struct {
		Schema                                                                    int
		Operation, Device, Descriptor, Generation, Broker, Platform, Architecture string
		Scope                                                                     access.Scope
		Identity                                                                  netbirdcommand.Identity
		CertificateExpiresAt                                                      time.Time
		Consumer                                                                  int64
		Journal                                                                   string
		Absent                                                                    bool
	}{1, "uninstall", device, r.review.DescriptorDigest, generation, broker, platform, architecture, scope, r.identity, r.identityExpiresAt.UTC(), consumer, r.review.Journal.Revision, r.review.Absent})
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/removal-review/v1\x00"), data...))
	clear(data)
	r.review.Revision = hex.EncodeToString(hash[:])
	return r, nil
}

func removalAudit(ctx context.Context, tx *sql.Tx, actor string, r *NetbirdRemoval, action, result string) error {
	return netbirdOperationAudit(ctx, tx, &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Operation: "uninstall"}, actor, action, result)
}

func (s *NetbirdRemovalStore) Review(parent context.Context, actor string, scope access.Scope, device string) (*NetbirdRemovalReview, error) {
	if parent == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 35*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := s.source(ctx, tx, scope, device)
	if err != nil {
		return nil, err
	}
	if err = removalAudit(ctx, tx, actor, &NetbirdRemoval{DeviceID: device, Scope: scope}, "review", "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &r.review, nil
}

const removalColumns = `id::text,device_id,tenant_id,site_id,actor,revision,journal_revision,descriptor_digest,descriptor,requested_at,expires_at,coalesce(cancellation_id::text,''),coalesce(cancelled_by,''),cancelled_at,completed_at,released_at,coalesce(released_by,''),coalesce(resolution_id::text,'')`

func scanRemoval(row interface{ Scan(...any) error }) (*NetbirdRemoval, error) {
	var r NetbirdRemoval
	var data []byte
	err := row.Scan(&r.ID, &r.DeviceID, &r.Scope.TenantID, &r.Scope.SiteID, &r.Actor, &r.Revision, &r.JournalRevision, &r.DescriptorDigest, &data, &r.RequestedAt, &r.ExpiresAt, &r.CancellationID, &r.CancelledBy, &r.CancelledAt, &r.CompletedAt, &r.ReleasedAt, &r.ReleasedBy, &r.ResolutionID)
	if err != nil {
		return nil, err
	}
	r.Descriptor, err = packageapi.DecodeRemoval(data)
	if err != nil {
		return nil, ErrNetbirdOperationConflict
	}
	digest, err := r.Descriptor.Digest()
	if err != nil || digest != r.DescriptorDigest {
		return nil, ErrNetbirdOperationConflict
	}
	return &r, nil
}

// All request families call this under the same UUID and device advisory locks.
// The corresponding database trigger also excludes direct cross-family inserts.
func netbirdRequestConflict(ctx context.Context, tx *sql.Tx, device, id string) (bool, error) {
	var pending bool
	err := tx.QueryRowContext(ctx, `SELECT
 EXISTS(SELECT 1 FROM uem_netbird_operations WHERE id=$2 OR (device_id=$1 AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL))))
 OR EXISTS(SELECT 1 FROM uem_netbird_registrations WHERE id=$2 OR (device_id=$1 AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL))))
 OR EXISTS(SELECT 1 FROM uem_netbird_installations WHERE id=$2 OR (device_id=$1 AND cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL))
 OR EXISTS(SELECT 1 FROM uem_netbird_removals WHERE id=$2 OR (device_id=$1 AND cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL))
 OR EXISTS(SELECT 1 FROM uem_netbird_removal_recoveries WHERE id=$2 OR (device_id=$1 AND cancelled_at IS NULL AND completed_at IS NULL))`, device, id).Scan(&pending)
	return pending, err
}

func (s *NetbirdRemovalStore) Request(parent context.Context, actor string, scope access.Scope, device, id, digest, revision string) (*NetbirdRemoval, error) {
	if parent == nil || !canonicalRequestID(device) || !canonicalRequestID(id) || !netbirdcommand.ValidDigest(digest) || !netbirdcommand.ValidDigest(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 35*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629916,hashtext($1))`, id); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629914,hashtext($1))`, device); err != nil {
		return nil, err
	}
	r, err := scanRemoval(tx.QueryRowContext(ctx, `SELECT `+removalColumns+` FROM uem_netbird_removals WHERE id=$1`, id))
	if err == nil {
		if r.DeviceID != device || r.Scope != scope || r.Actor != actor || r.Revision != revision || r.DescriptorDigest != digest {
			return nil, ErrNetbirdOperationConflict
		}
		if err = removalAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return r, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	pending, err := netbirdRequestConflict(ctx, tx, device, id)
	if err != nil {
		return nil, err
	}
	if pending {
		return nil, ErrNetbirdOperationConflict
	}
	source, err := s.source(ctx, tx, scope, device)
	if err != nil {
		return nil, err
	}
	if source.review.Absent || source.review.Revision != revision || source.review.DescriptorDigest != digest {
		return nil, ErrNetbirdOperationChanged
	}
	data, err := packageapi.EncodeRemoval(source.review.Descriptor)
	if err != nil {
		return nil, err
	}
	r, err = scanRemoval(tx.QueryRowContext(ctx, `WITH stamp AS(SELECT clock_timestamp() AS at) INSERT INTO uem_netbird_removals(id,device_id,tenant_id,site_id,actor,revision,journal_revision,descriptor_digest,descriptor,requested_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,at,least(at+interval '10 minutes',$10) FROM stamp WHERE at<$10 RETURNING `+removalColumns, id, device, scope.TenantID, scope.SiteID, actor, revision, source.review.Journal.Revision, digest, string(data), source.identityExpiresAt))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNetbirdOperationChanged
	}
	if err != nil {
		return nil, err
	}
	if err = removalAudit(ctx, tx, actor, r, "request", "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *NetbirdRemovalStore) Read(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdRemoval, error) {
	if parent == nil || !canonicalRequestID(device) || !canonicalRequestID(id) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.ReadSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := scanRemoval(tx.QueryRowContext(ctx, `SELECT `+removalColumns+` FROM uem_netbird_removals WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = removalAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

// Cancellation applies only before native delivery. An admitted attempt retains
// its original outcome and requires separately reviewed recovery.
func (s *NetbirdRemovalStore) Cancel(parent context.Context, actor string, scope access.Scope, device, id, revision, cancellation string) (*NetbirdRemoval, error) {
	if parent == nil || !canonicalRequestID(device) || !canonicalRequestID(id) || !canonicalRequestID(cancellation) || cancellation == id || !netbirdcommand.ValidDigest(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629914,hashtext($1))`, device); err != nil {
		return nil, err
	}
	r, err := scanRemoval(tx.QueryRowContext(ctx, `SELECT `+removalColumns+` FROM uem_netbird_removals WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR UPDATE`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if r.Revision != revision {
		return nil, ErrNetbirdOperationConflict
	}
	if r.CancelledAt != nil {
		if r.CancellationID != cancellation || r.CancelledBy != actor {
			return nil, ErrNetbirdOperationConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return r, nil
	}
	var attempted bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_netbird_removal_attempts WHERE request_id=$1)`, id).Scan(&attempted); err != nil {
		return nil, err
	}
	if attempted || r.CompletedAt != nil || r.ReleasedAt != nil {
		return nil, ErrNetbirdOperationConflict
	}
	r, err = scanRemoval(tx.QueryRowContext(ctx, `UPDATE uem_netbird_removals SET cancellation_id=$2,cancelled_by=$3,cancelled_at=clock_timestamp() WHERE id=$1 RETURNING `+removalColumns, id, cancellation, actor))
	if err != nil {
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "23505" {
			return nil, ErrNetbirdOperationConflict
		}
		return nil, err
	}
	if err = removalAudit(ctx, tx, actor, r, "stopped", "cancelled"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}
