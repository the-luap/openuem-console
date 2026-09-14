package inventory

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// NetbirdInstallationExecutor sends one admitted version-three command. It must
// bound local waiting and return only a correlated receipt, without redelivery.
type NetbirdInstallationExecutor func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error)

func NewNetbirdInstallationDeliveryStore(db *sql.DB, permissions *access.Store, individual bool, master string, control NetbirdOperationControl, prepare NetbirdPreparationExecutor, execute NetbirdInstallationExecutor) (*NetbirdInstallationStore, error) {
	if execute == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	s, err := NewNetbirdInstallationPreparationStore(db, permissions, individual, master, control, prepare)
	if err != nil {
		return nil, err
	}
	s.execute, s.control = execute, control
	return s, nil
}

// Public delivery history contains receipt metadata, never the private package,
// certificate, source URL or executable envelope. Pending is not retry authority.
type NetbirdInstallationDelivery struct {
	RequestID, CommandHash, Outcome            string
	IssuedAt, ExpiresAt                        time.Time
	RecordedAt, CompletedAt                    *time.Time
	Receipt                                    *netbirdcommand.Receipt
	ObservationID, ObservedBy, ObservedOutcome string
	ObservedAt                                 *time.Time
}

func readInstallationDelivery(ctx context.Context, tx *sql.Tx, id string) (*NetbirdInstallationDelivery, error) {
	var d NetbirdInstallationDelivery
	var receipt []byte
	err := tx.QueryRowContext(ctx, `SELECT a.request_id::text,a.command_hash,a.issued_at,a.expires_at,
 CASE WHEN i.completed_at IS NOT NULL THEN 'completed' ELSE coalesce(r.outcome,'pending') END,r.recorded_at,i.completed_at,
 coalesce((SELECT o.response->'receipt' FROM uem_netbird_installation_observations o WHERE o.request_id=i.id AND o.recorded_at=i.completed_at AND o.response->'receipt'->>'status'='completed' LIMIT 1),r.receipt),
 coalesce(o.id::text,''),coalesce(o.actor,''),coalesce(CASE WHEN o.response->>'outcome'='ok' THEN o.response->'receipt'->>'status' ELSE coalesce(o.response->>'outcome','unavailable') END,''),o.recorded_at
 FROM uem_netbird_installation_attempts a JOIN uem_netbird_installations i ON i.id=a.request_id LEFT JOIN uem_netbird_installation_results r USING(request_id)
 LEFT JOIN LATERAL(SELECT * FROM uem_netbird_installation_observations WHERE request_id=a.request_id ORDER BY recorded_at DESC,id DESC LIMIT 1) o ON true
 WHERE a.request_id=$1`, id).Scan(&d.RequestID, &d.CommandHash, &d.IssuedAt, &d.ExpiresAt, &d.Outcome, &d.RecordedAt, &d.CompletedAt, &receipt, &d.ObservationID, &d.ObservedBy, &d.ObservedOutcome, &d.ObservedAt)
	if err != nil {
		return nil, err
	}
	if len(receipt) > 0 {
		r, err := netbirdcommand.DecodeReceipt(receipt)
		if err != nil || r.RequestID != id || r.CommandHash != d.CommandHash || r.Operation != "install" {
			return nil, ErrNetbirdOperationConflict
		}
		d.Receipt = &r
	}
	if d.ObservedAt == nil {
		d.ObservedOutcome = ""
	}
	return &d, nil
}

func installationStageAudit(ctx context.Context, tx *sql.Tx, r *NetbirdInstallation, actor, action, stage string) error {
	return netbirdOperationAudit(ctx, tx, &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Operation: "install/" + stage}, actor, action, "recorded")
}

func (s *NetbirdInstallationStore) installationRecord(ctx context.Context, actor string, scope access.Scope, device, id, revision string, capability access.Capability) (*sql.Tx, *NetbirdInstallation, error) {
	if !canonicalRequestID(device) || !canonicalRequestID(id) || !netbirdcommand.ValidDigest(revision) {
		return nil, nil, ErrNetbirdOperationInvalid
	}
	tx, err := s.begin(ctx, actor, scope, capability)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*sql.Tx, *NetbirdInstallation, error) { tx.Rollback(); return nil, nil, err }
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629914,hashtext($1))`, device); err != nil {
		return fail(err)
	}
	r, err := scanInstallation(tx.QueryRowContext(ctx, `SELECT `+installationColumns+` FROM uem_netbird_installations WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR UPDATE`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return fail(err)
	}
	if r.Revision != revision {
		return fail(ErrNetbirdOperationConflict)
	}
	return tx, r, nil
}

// Install consumes an exact prepared request once. Admission and its audit commit
// before native delivery; no database transaction spans the installer process.
func (s *NetbirdInstallationStore) Install(parent context.Context, actor string, scope access.Scope, device, id, revision string) (*NetbirdInstallationDelivery, error) {
	if parent == nil || s.execute == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	r, d, c, err := s.admitInstallation(parent, actor, scope, device, id, revision)
	if err != nil || c == nil {
		return d, err
	}
	call, cancel := context.WithDeadline(parent, c.ExpiresAt)
	defer cancel()
	var receipt *netbirdcommand.Receipt
	if call.Err() == nil {
		receipt, err = s.execute(call, *c)
	}
	if err != nil || call.Err() != nil || receipt == nil || !receipt.Matches(*c) {
		receipt = nil
	}
	record, stop := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer stop()
	return s.finishInstallation(record, r, receipt)
}

func (s *NetbirdInstallationStore) admitInstallation(parent context.Context, actor string, scope access.Scope, device, id, revision string) (*NetbirdInstallation, *NetbirdInstallationDelivery, *netbirdcommand.Command, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.installationRecord(ctx, actor, scope, device, id, revision, access.AssignSoftware)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback()
	if r.Actor != actor {
		return nil, nil, nil, ErrNetbirdOperationConflict
	}
	d, err := readInstallationDelivery(ctx, tx, id)
	if err == nil {
		if err = installationAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
			return nil, nil, nil, err
		}
		return r, d, nil, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil, err
	}
	if r.CancelledAt != nil || r.CompletedAt != nil || !time.Now().Before(r.ExpiresAt) {
		return nil, nil, nil, ErrNetbirdOperationConflict
	}
	// Reconstruct the original private request rather than trusting a prepared
	// label or a matching payload SHA alone. Its source remains encrypted at rest.
	var p netbirdcommand.PreparationRequest
	var hash string
	var response []byte
	err = tx.QueryRowContext(ctx, `SELECT p.wire_version,p.certificate_hash,p.request_hash,p.issued_at,p.expires_at,r.response FROM uem_netbird_preparations p JOIN uem_netbird_preparation_results r USING(request_id) WHERE p.request_id=$1 AND r.outcome='prepared'`, id).Scan(&p.Version, &p.CertificateHash, &hash, &p.IssuedAt, &p.ExpiresAt, &response)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNetbirdOperationNotReady
	}
	if err != nil {
		return nil, nil, nil, err
	}
	source, err := s.source(ctx, tx, scope, device, r.ApprovalID, r.ApprovalDigest)
	if err != nil {
		return nil, nil, nil, err
	}
	if source.review.Revision != revision || source.review.Journal.Revision != r.JournalRevision || source.identity.CertificateHash != p.CertificateHash {
		return nil, nil, nil, ErrNetbirdOperationChanged
	}
	p.Identity, p.RequestID, p.Revision, p.JournalRevision, p.Package = source.identity, id, revision, r.JournalRevision, source.packageDescriptor
	p.IssuedAt, p.ExpiresAt = p.IssuedAt.UTC(), p.ExpiresAt.UTC()
	actual, err := p.Digest()
	if err != nil || actual != hash || !p.Executable(source.identity, time.Now()) {
		return nil, nil, nil, ErrNetbirdOperationChanged
	}
	prepared, err := netbirdcommand.DecodePreparationResponse(response, p)
	if err != nil || prepared.Outcome != "prepared" {
		return nil, nil, nil, ErrNetbirdOperationChanged
	}
	var issued time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&issued); err != nil {
		return nil, nil, nil, err
	}
	issued = issued.UTC()
	expires := issued.Add(netbirdcommand.InstallationLifetime)
	if source.identityExpiresAt.Before(expires) {
		expires = source.identityExpiresAt.UTC()
	}
	c := netbirdcommand.Command{Version: netbirdcommand.InstallationVersion, Identity: source.identity, RequestID: id, Revision: revision, Operation: "install", IssuedAt: issued, ExpiresAt: expires, Package: source.packageDescriptor}
	digest, err := c.Digest()
	if err != nil || !c.Executable(source.identity, time.Now()) || issued.Before(p.IssuedAt) {
		return nil, nil, nil, ErrNetbirdOperationChanged
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_installation_attempts(request_id,wire_version,certificate_hash,command_hash,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, id, c.Version, c.CertificateHash, digest, c.IssuedAt, c.ExpiresAt)
	if err != nil {
		return nil, nil, nil, err
	}
	if err = installationStageAudit(ctx, tx, r, actor, "attempt", "deliver"); err != nil {
		return nil, nil, nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, nil, err
	}
	return r, nil, &c, nil
}

func (s *NetbirdInstallationStore) finishInstallation(ctx context.Context, r *NetbirdInstallation, receipt *netbirdcommand.Receipt) (*NetbirdInstallationDelivery, error) {
	tx, err := s.packages.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var locked string
	if err = tx.QueryRowContext(ctx, `SELECT id::text FROM uem_netbird_installations WHERE id=$1 FOR UPDATE`, r.ID).Scan(&locked); err != nil {
		return nil, err
	}
	outcome := "unconfirmed"
	var data any
	if receipt != nil {
		wire, err := netbirdcommand.EncodeReceipt(*receipt)
		if err != nil {
			return nil, ErrNetbirdOperationConflict
		}
		data = string(wire)
		if receipt.Status == "completed" {
			outcome = "completed"
		}
	}
	var recorded time.Time
	err = tx.QueryRowContext(ctx, `INSERT INTO uem_netbird_installation_results(request_id,outcome,receipt) VALUES($1,$2,$3::jsonb) RETURNING recorded_at`, r.ID, outcome, data).Scan(&recorded)
	if err != nil {
		return nil, err
	}
	if outcome == "completed" {
		if _, err = tx.ExecContext(ctx, `UPDATE uem_netbird_installations SET completed_at=$2 WHERE id=$1 AND completed_at IS NULL`, r.ID, recorded); err != nil {
			return nil, err
		}
	}
	if err = installationStageAudit(ctx, tx, r, r.Actor, "attempt", "result-"+outcome); err != nil {
		return nil, err
	}
	d, err := readInstallationDelivery(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *NetbirdInstallationStore) ReadDelivery(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdInstallationDelivery, error) {
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
	r, err := scanInstallation(tx.QueryRowContext(ctx, `SELECT `+installationColumns+` FROM uem_netbird_installations WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d, err := readInstallationDelivery(ctx, tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = installationAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d, nil
}
