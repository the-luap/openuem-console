package inventory

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/nats/netbirdapi"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// NetbirdRegistrationStore stages provider key creation, one command delivery,
// and exact-key cleanup. It never derives provider peer ownership from a report.
// Construction does not start a dispatcher or enable a legacy registration route.
type NetbirdRegistrationStore struct {
	operations *NetbirdOperationStore
	cipher     cipher.AEAD
	master     string
	transport  http.RoundTripper
}

func NewNetbirdRegistrationStore(db *sql.DB, permissions *access.Store, individual bool, master string, transport http.RoundTripper, control NetbirdOperationControl, execute NetbirdOperationExecutor) (*NetbirdRegistrationStore, error) {
	aead, err := registrationCipher(master)
	if err != nil || control == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	inspect := func(ctx context.Context, identity netbirdcommand.Identity) (netbirdcommand.State, error) {
		now := time.Now().UTC()
		c := netbirdcommand.ControlRequest{Version: netbirdcommand.Version, Identity: identity, RequestID: uuid.NewString(), Kind: "registration-state", IssuedAt: now, ExpiresAt: now.Add(2 * time.Second)}
		if deadline, ok := ctx.Deadline(); ok && deadline.Before(c.ExpiresAt) {
			c.ExpiresAt = deadline
		}
		if !c.Valid() {
			return netbirdcommand.State{}, ErrNetbirdOperationNotReady
		}
		response, err := control(ctx, c)
		if err != nil || ctx.Err() != nil || response == nil || !response.Matches(c) || response.Outcome != "ok" {
			return netbirdcommand.State{}, ErrNetbirdOperationNotReady
		}
		return response.State, nil
	}
	operations, err := NewNetbirdOperationStore(db, permissions, individual, inspect, execute)
	if err != nil {
		return nil, err
	}
	return &NetbirdRegistrationStore{operations, aead, master, transport}, nil
}

// Public records expose policy and evidence, never the provider token or key.
// Completed means a matching command receipt plus confirmed key removal; it
// does not claim a lasting connection, group membership, or owned provider peer.
type NetbirdRegistration struct {
	CommandHash, ReleasedBy                       string
	ReleasedAt                                    *time.Time
	Resolution                                    *NetbirdRegistrationResolution
	LastCleanupRetry                              *NetbirdCleanupRetry
	PeerBinding                                   *NetbirdPeerBinding
	ID, DeviceID, Actor, Revision, Status, Reason string
	Scope                                         access.Scope
	Individual, ExtraDNS                          bool
	Groups                                        []string
	RequestedAt, ExpiresAt                        time.Time
	FinishedAt                                    *time.Time
	Key                                           *netbirdapi.ManagedKeyMetadata
	Delivered                                     *NetbirdOperationResult
	KeyAbsent                                     bool
	Attempts                                      []string
	snapshot                                      string
}

func (r NetbirdRegistration) String() string   { return "NetBird registration (credentials redacted)" }
func (r NetbirdRegistration) GoString() string { return r.String() }

type NetbirdRegistrationReview struct {
	GroupChoices            []nats.NetBirdGroups
	Target                  ManualTarget
	Revision, ManagementURL string
	Groups                  []string
	ExtraDNS                bool
	Journal                 netbirdcommand.State
}

type registrationSnapshot struct {
	Base, Token       string
	Identity          netbirdcommand.Identity
	IdentityExpiresAt time.Time
}

func (r registrationSnapshot) String() string {
	return "NetBird registration snapshot (credentials redacted)"
}
func (r registrationSnapshot) GoString() string { return r.String() }

func registrationGroups(groups []string, extra bool) ([]string, error) {
	policy := netbirdapi.ManagedKeyRequest{RequestID: "10000000-0000-4000-8000-000000000001", Groups: groups, ExtraDNS: extra}
	if _, err := policy.Digest(); err != nil {
		return nil, ErrNetbirdOperationInvalid
	}
	result := append([]string{}, groups...)
	slices.Sort(result)
	return result, nil
}

func (s *NetbirdRegistrationStore) source(ctx context.Context, tx *sql.Tx, scope access.Scope, device string, groups []string, extra bool) (*NetbirdRegistrationReview, registrationSnapshot, error) {
	var snapshot registrationSnapshot
	groups, err := registrationGroups(groups, extra)
	if err != nil {
		return nil, snapshot, err
	}
	source, err := s.operations.operationSource(ctx, tx, scope, device, "register", "")
	if err != nil {
		return nil, snapshot, err
	}
	// The common source holds the tenant/settings generation and installation
	// locks. Read and authenticate its bounded token only after live capability.
	var token string
	err = tx.QueryRowContext(ctx, `SELECT coalesce(n.access_token,'') FROM netbird_settings n JOIN tenants t ON t.tenant_netbird=n.id WHERE t.id=$1 AND coalesce(octet_length(n.access_token),0)<=$2 FOR SHARE OF n`, scope.TenantID, legacysecret.MaxStoredSize).Scan(&token)
	if err != nil {
		return nil, snapshot, ErrNetbirdOperationChanged
	}
	token, err = legacysecret.Open(token, s.master)
	if err != nil || token == "" {
		return nil, snapshot, ErrNetbirdOperationChanged
	}
	lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
	available, err := netbirdapi.Groups(lookup, s.transport, source.ManagementURL, token)
	lookupErr := lookup.Err()
	cancel()
	if err != nil || lookupErr != nil {
		return nil, snapshot, ErrNetbirdOperationNotReady
	}
	for _, selected := range groups {
		found := false
		for _, group := range available {
			if group.ID == selected {
				found = true
				break
			}
		}
		if !found {
			return nil, snapshot, ErrNetbirdOperationChanged
		}
	}
	data, _ := json.Marshal([]any{source.Revision, groups, extra})
	digest := sha256.Sum256(data)
	review := &NetbirdRegistrationReview{Target: source.Target, Revision: hex.EncodeToString(digest[:]), ManagementURL: source.ManagementURL, Groups: groups, ExtraDNS: extra, Journal: source.Journal}
	review.GroupChoices = available
	snapshot = registrationSnapshot{source.ManagementURL, token, source.identity, source.identityExpiresAt}
	return review, snapshot, nil
}

func registrationAudit(ctx context.Context, db refreshExecutor, r *NetbirdRegistration, actor, action, stage string) error {
	op := "register"
	if stage != "" {
		op += "/" + stage
	}
	return netbirdOperationAudit(ctx, db, &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Operation: op}, actor, action, "recorded")
}

func (s *NetbirdRegistrationStore) Review(parent context.Context, actor string, scope access.Scope, device string, groups []string, extra bool) (*NetbirdRegistrationReview, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.operations.recordTx(ctx, actor, scope, access.ManageDeviceSecurity)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	review, _, err := s.source(ctx, tx, scope, device, groups, extra)
	if err != nil {
		return nil, err
	}
	if err = registrationAudit(ctx, tx, &NetbirdRegistration{DeviceID: device, Scope: scope}, actor, "review", ""); err != nil {
		return nil, err
	}
	return review, tx.Commit()
}

const registrationColumns = `r.id,r.device_id,r.tenant_id,r.site_id,r.actor,r.individual,r.revision,r.groups,r.extra_dns,r.snapshot,r.status,r.reason,r.requested_at,r.expires_at,r.finished_at,r.released_at,r.released_by`

func scanRegistration(row interface{ Scan(...any) error }) (*NetbirdRegistration, error) {
	r := &NetbirdRegistration{}
	var groups []byte
	var finished, released sql.NullTime
	var releasedBy sql.NullString
	err := row.Scan(&r.ID, &r.DeviceID, &r.Scope.TenantID, &r.Scope.SiteID, &r.Actor, &r.Individual, &r.Revision, &groups, &r.ExtraDNS, &r.snapshot, &r.Status, &r.Reason, &r.RequestedAt, &r.ExpiresAt, &finished, &released, &releasedBy)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(groups, &r.Groups); err != nil {
		return nil, ErrNetbirdOperationInvalid
	}
	if finished.Valid {
		r.FinishedAt = &finished.Time
	}
	if released.Valid {
		r.ReleasedAt = &released.Time
	}
	r.ReleasedBy = releasedBy.String
	return r, nil
}

func (s *NetbirdRegistrationStore) Request(parent context.Context, actor string, scope access.Scope, device, id, revision string, groups []string, extra bool) (*NetbirdRegistration, error) {
	groups, err := registrationGroups(groups, extra)
	if err != nil || !canonicalRequestID(id) || !ValidReportDeviceID(device) || !validManualRevision(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.operations.recordTx(ctx, actor, scope, access.ManageDeviceSecurity)
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
	r, err := scanRegistration(tx.QueryRowContext(ctx, `SELECT `+registrationColumns+` FROM uem_netbird_registrations r WHERE id=$1`, id))
	if err == nil {
		if r.Actor != actor || r.Scope != scope || r.DeviceID != device || r.Revision != revision || r.Individual != s.operations.individual || r.ExtraDNS != extra || !slices.Equal(r.Groups, groups) {
			return nil, ErrNetbirdOperationConflict
		}
		if err = registrationAudit(ctx, tx, r, actor, "read", ""); err != nil {
			return nil, err
		}
		return r, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var pending bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_netbird_operations WHERE id=$2 OR (device_id=$1 AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))) OR EXISTS(SELECT 1 FROM uem_netbird_registrations WHERE device_id=$1 AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))`, device, id).Scan(&pending)
	if err != nil {
		return nil, err
	}
	if pending {
		return nil, ErrNetbirdOperationConflict
	}
	review, snapshot, err := s.source(ctx, tx, scope, device, groups, extra)
	if err != nil {
		return nil, err
	}
	if review.Revision != revision {
		return nil, ErrNetbirdOperationChanged
	}
	r = &NetbirdRegistration{ID: id, DeviceID: device, Actor: actor, Scope: scope, Individual: s.operations.individual, Revision: revision, Groups: groups, ExtraDNS: extra}
	plain, err := json.Marshal(snapshot)
	if err != nil {
		return nil, ErrNetbirdOperationInvalid
	}
	defer clear(plain)
	r.snapshot, err = sealRegistration(s.cipher, r, "provider", "", plain)
	if err != nil {
		return nil, err
	}
	data, _ := json.Marshal(groups)
	_, err = tx.ExecContext(ctx, `WITH stamp AS (SELECT clock_timestamp() AS at) INSERT INTO uem_netbird_registrations(id,device_id,tenant_id,site_id,actor,individual,revision,groups,extra_dns,snapshot,requested_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,at,at+interval '2 minutes' FROM stamp`, id, device, scope.TenantID, scope.SiteID, actor, r.Individual, revision, string(data), extra, r.snapshot)
	if err != nil {
		return nil, err
	}
	r, err = scanRegistration(tx.QueryRowContext(ctx, `SELECT `+registrationColumns+` FROM uem_netbird_registrations r WHERE id=$1`, id))
	if err != nil {
		return nil, err
	}
	if err = registrationAudit(ctx, tx, r, actor, "request", ""); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	select {
	case s.operations.wake <- struct{}{}:
	default:
	}
	return r, nil
}

func recordedRegistration(ctx context.Context, tx *sql.Tx, scope access.Scope, device, id, lock string) (*NetbirdRegistration, error) {
	r, err := scanRegistration(tx.QueryRowContext(ctx, `SELECT `+registrationColumns+` FROM uem_netbird_registrations r WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 `+lock, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func (s *NetbirdRegistrationStore) Read(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdRegistration, error) {
	if !canonicalRequestID(id) || !ValidReportDeviceID(device) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.operations.recordTx(ctx, actor, scope, access.ReadDevices)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := recordedRegistration(ctx, tx, scope, device, id, "FOR SHARE OF r")
	if err != nil {
		return nil, err
	}
	if _, err = registrationEvidence(ctx, tx, r); err != nil {
		return nil, err
	}
	r.Resolution, err = readRegistrationResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	if err = registrationAudit(ctx, tx, r, actor, "read", ""); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}

func finishRegistration(ctx context.Context, tx *sql.Tx, r *NetbirdRegistration, status, reason string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE uem_netbird_registrations SET status=$2,reason=$3,finished_at=clock_timestamp() WHERE id=$1`, r.ID, status, reason); err != nil {
		return err
	}
	if err := registrationAudit(ctx, tx, r, r.Actor, status, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *NetbirdRegistrationStore) Cancel(parent context.Context, actor string, scope access.Scope, device, id string) error {
	if !canonicalRequestID(id) || !ValidReportDeviceID(device) {
		return ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.operations.recordTx(ctx, actor, scope, access.ManageDeviceSecurity)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := recordedRegistration(ctx, tx, scope, device, id, "FOR UPDATE OF r")
	if err != nil {
		return err
	}
	if _, err = registrationEvidence(ctx, tx, r); err != nil {
		return err
	}
	if r.Status != "queued" || len(r.Attempts) > 0 {
		return ErrNetbirdOperationConflict
	}
	// Cancellation is authorized to the caller; retain that attribution.
	if _, err = tx.ExecContext(ctx, `UPDATE uem_netbird_registrations SET status='stopped',reason='cancelled',finished_at=clock_timestamp() WHERE id=$1`, r.ID); err != nil {
		return err
	}
	if err = registrationAudit(ctx, tx, r, actor, "stopped", ""); err != nil {
		return err
	}
	return tx.Commit()
}

// ReconcileCleanup only observes the exact retained key after a prior DELETE
// attempt. It never creates, delivers, or deletes anything. Positive absence is
// additional evidence; the original uncertain outcome and device barrier remain.
func (s *NetbirdRegistrationStore) ReconcileCleanup(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdRegistration, error) {
	if !canonicalRequestID(id) || !ValidReportDeviceID(device) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.operations.recordTx(ctx, actor, scope, access.ManageDeviceSecurity)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := recordedRegistration(ctx, tx, scope, device, id, "FOR UPDATE OF r")
	if err != nil {
		return nil, err
	}
	if _, err = registrationEvidence(ctx, tx, r); err != nil {
		return nil, err
	}
	if r.Status != "unconfirmed" || r.Key == nil || !slices.Contains(r.Attempts, "delete") {
		return nil, ErrNetbirdOperationConflict
	}
	if !r.KeyAbsent {
		if r.Individual != s.operations.individual {
			return nil, ErrNetbirdOperationChanged
		}
		manual := &ManualExecutionStore{db: s.operations.db, permissions: s.operations.permissions, individual: s.operations.individual}
		if _, err = manual.target(ctx, tx, scope, device); err != nil {
			return nil, err
		}
		snapshot, err := s.snapshot(r)
		if err != nil {
			return nil, err
		}
		observed, absent, err := s.observe(ctx, snapshot, r.Key.ID)
		if err != nil {
			return nil, ErrNetbirdOperationNotReady
		}
		if !absent && (observed == nil || !r.Key.SameOwnership(*observed)) {
			return nil, ErrNetbirdOperationChanged
		}
		if absent {
			data, _ := json.Marshal(struct {
				KeyID  string `json:"key_id"`
				Absent bool   `json:"absent"`
			}{r.Key.ID, true})
			if _, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_registration_evidence(request_id,kind,data) VALUES($1,'absent',$2)`, r.ID, string(data)); err != nil {
				return nil, err
			}
			r.KeyAbsent = true
		}
	}
	if err = registrationAudit(ctx, tx, r, actor, "read", "cleanup-evidence"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}

// History returns stable, bounded pages in the recorded scope after a move or
// removal. It does not decrypt credentials, contact providers, or query agents.
func (s *NetbirdRegistrationStore) History(parent context.Context, actor string, scope access.Scope, device, before string) ([]NetbirdRegistration, error) {
	if !ValidReportDeviceID(device) || before != "" && !canonicalRequestID(before) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.operations.recordTx(ctx, actor, scope, access.ReadDevices)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	id := "ffffffff-ffff-ffff-ffff-ffffffffffff"
	if before != "" {
		r, err := recordedRegistration(ctx, tx, scope, device, before, "")
		if err != nil {
			return nil, err
		}
		at, id = r.RequestedAt, r.ID
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+registrationColumns+` FROM uem_netbird_registrations r WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND (requested_at,id)<($4,$5::uuid) ORDER BY requested_at DESC,id DESC LIMIT 50`, device, scope.TenantID, scope.SiteID, at, id)
	if err != nil {
		return nil, err
	}
	result := []NetbirdRegistration{}
	for rows.Next() {
		r, err := scanRegistration(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		r.snapshot = ""
		result = append(result, *r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err = registrationAudit(ctx, tx, &NetbirdRegistration{DeviceID: device, Scope: scope}, actor, "read", "history"); err != nil {
		return nil, err
	}
	return result, tx.Commit()
}
