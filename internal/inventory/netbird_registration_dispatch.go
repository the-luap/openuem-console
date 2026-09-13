package inventory

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/open-uem/nats/netbirdapi"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// Read after locking the request: independent evidence may have committed while
// the locking SELECT was waiting, after its original MVCC snapshot was taken.
func registrationEvidence(ctx context.Context, tx *sql.Tx, r *NetbirdRegistration) (string, error) {
	r.Attempts = []string{}
	r.Key, r.Delivered, r.KeyAbsent = nil, nil, false
	rows, err := tx.QueryContext(ctx, `SELECT stage FROM uem_netbird_registration_attempts WHERE request_id=$1 AND revision=$2 ORDER BY created_at,stage`, r.ID, r.Revision)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var stage string
		if err = rows.Scan(&stage); err != nil {
			rows.Close()
			return "", err
		}
		r.Attempts = append(r.Attempts, stage)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	rows, err = tx.QueryContext(ctx, `SELECT kind,data,secret FROM uem_netbird_registration_evidence WHERE request_id=$1`, r.ID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	secret := ""
	for rows.Next() {
		var kind, sealed string
		var data []byte
		if err = rows.Scan(&kind, &data, &sealed); err != nil {
			return "", err
		}
		switch kind {
		case "key":
			r.Key = &netbirdapi.ManagedKeyMetadata{}
			if err = json.Unmarshal(data, r.Key); err != nil {
				return "", ErrNetbirdOperationInvalid
			}
			secret = sealed
		case "delivered":
			r.Delivered = &NetbirdOperationResult{}
			if err = json.Unmarshal(data, r.Delivered); err != nil {
				return "", ErrNetbirdOperationInvalid
			}
		case "absent":
			r.KeyAbsent = true
		}
	}
	return secret, rows.Err()
}

func (s *NetbirdRegistrationStore) attempt(ctx context.Context, r *NetbirdRegistration, stage, digest string) error {
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_registration_attempts(request_id,stage,revision,digest) VALUES($1,$2,$3,$4)`, r.ID, stage, r.Revision, digest)
	if err != nil {
		return err
	}
	if err = registrationAudit(ctx, tx, r, r.Actor, "attempt", stage); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	r.Attempts = append(r.Attempts, stage)
	return nil
}

func (s *NetbirdRegistrationStore) evidence(ctx context.Context, r *NetbirdRegistration, kind string, value any, secret string) error {
	data, err := json.Marshal(value)
	if err != nil {
		return ErrNetbirdOperationInvalid
	}
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_registration_evidence(request_id,kind,data,secret) VALUES($1,$2,$3,$4)`, r.ID, kind, string(data), secret)
	if err != nil {
		return err
	}
	if err = registrationAudit(ctx, tx, r, r.Actor, "attempt", "evidence-"+kind); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *NetbirdRegistrationStore) snapshot(r *NetbirdRegistration) (registrationSnapshot, error) {
	var snapshot registrationSnapshot
	plain, err := openRegistration(s.cipher, r, "provider", "", r.snapshot)
	if err != nil {
		return snapshot, err
	}
	defer clear(plain)
	if json.Unmarshal(plain, &snapshot) != nil || !netbirdapi.ValidBase(snapshot.Base) || snapshot.Token == "" || !snapshot.Identity.Valid() || snapshot.Identity.DeviceID != r.DeviceID || snapshot.Identity.TenantID != int64(r.Scope.TenantID) || snapshot.Identity.SiteID != int64(r.Scope.SiteID) || snapshot.Identity.Individual != r.Individual {
		return registrationSnapshot{}, ErrNetbirdOperationInvalid
	}
	return snapshot, nil
}

func (s *NetbirdRegistrationStore) observe(ctx context.Context, snapshot registrationSnapshot, keyID string) (*netbirdapi.ManagedKeyMetadata, bool, error) {
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	metadata, absent, err := netbirdapi.ObserveManagedKey(call, s.transport, snapshot.Base, snapshot.Token, keyID)
	if call.Err() != nil {
		return nil, false, ErrNetbirdOperationNotReady
	}
	return metadata, absent, err
}

// Cleanup only uses the exact ID returned by creation and the original encrypted
// provider credential. A recorded DELETE attempt is never sent again. A later
// read may prove absence after a lost reply; other errors never mean absence.
func (s *NetbirdRegistrationStore) cleanup(ctx context.Context, r *NetbirdRegistration, snapshot registrationSnapshot) error {
	if r.Key == nil || r.KeyAbsent {
		return nil
	}
	observed, absent, err := s.observe(ctx, snapshot, r.Key.ID)
	if err != nil {
		return err
	}
	attempted := slices.Contains(r.Attempts, "delete")
	if !absent && (observed == nil || !r.Key.SameOwnership(*observed)) {
		return ErrNetbirdOperationChanged
	}
	if !attempted {
		data, _ := json.Marshal([]any{r.ID, r.Revision, r.Key.ID, r.Key})
		digest := sha256.Sum256(data)
		if err = s.attempt(ctx, r, "delete", hex.EncodeToString(digest[:])); err != nil {
			return err
		}
		if !absent {
			call, cancel := context.WithTimeout(ctx, 5*time.Second)
			// The following exact-ID read, rather than a DELETE acknowledgement,
			// establishes absence even when the mutation response was lost.
			_ = netbirdapi.DeleteKey(call, s.transport, snapshot.Base, snapshot.Token, r.Key.ID)
			cancel()
			_, absent, err = s.observe(ctx, snapshot, r.Key.ID)
			if err != nil {
				return err
			}
		}
	}
	if !absent {
		return ErrNetbirdOperationNotReady
	}
	if err = s.evidence(ctx, r, "absent", struct {
		KeyID  string `json:"key_id"`
		Absent bool   `json:"absent"`
	}{r.Key.ID, true}, ""); err != nil {
		return err
	}
	r.KeyAbsent = true
	return nil
}

func (s *NetbirdRegistrationStore) DispatchOne(parent context.Context) (bool, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute+25*time.Second)
	defer cancel()
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	r, err := scanRegistration(tx.QueryRowContext(ctx, `SELECT `+registrationColumns+` FROM uem_netbird_registrations r WHERE status='queued' ORDER BY requested_at,id FOR UPDATE OF r SKIP LOCKED LIMIT 1`))
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, err = registrationEvidence(ctx, tx, r)
	if err != nil {
		return true, err
	}
	finish := func(status, reason string) (bool, error) { return true, finishRegistration(ctx, tx, r, status, reason) }
	uncertain := func() (bool, error) { return finish("unconfirmed", "registration_unconfirmed") }
	created := slices.Contains(r.Attempts, "create")
	stop := func(reason string) (bool, error) {
		if created {
			return uncertain()
		}
		return finish("stopped", reason)
	}
	// Final evidence can be projected after rollback without any external call.
	if r.Delivered != nil && r.KeyAbsent {
		return finish("completed", "")
	}
	if r.KeyAbsent && !slices.Contains(r.Attempts, "deliver") {
		return finish("stopped", "recovered_without_delivery")
	}
	if r.Individual != s.operations.individual {
		return stop("mode_changed")
	}
	if !created && !time.Now().Before(r.ExpiresAt) {
		return stop("expired")
	}
	err = s.operations.permissions.AuthorizeTransaction(ctx, tx, r.Actor, access.ManageDeviceSecurity, r.Scope)
	if errors.Is(err, access.ErrDenied) {
		return stop("not_authorized")
	}
	if err != nil {
		return true, err
	}
	snapshot, err := s.snapshot(r)
	if err != nil {
		return stop("source_changed")
	}
	if created {
		// Recovery never repeats creation or registration. It may clean a retained
		// key once, while holding current device authority, then retain uncertainty.
		manual := &ManualExecutionStore{db: s.operations.db, permissions: s.operations.permissions, individual: s.operations.individual}
		if _, err = manual.target(ctx, tx, r.Scope, r.DeviceID); err != nil {
			return uncertain()
		}
		if r.Key == nil {
			return uncertain()
		}
		_ = s.cleanup(ctx, r, snapshot)
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		if r.KeyAbsent {
			if r.Delivered != nil {
				return finish("completed", "")
			}
			if !slices.Contains(r.Attempts, "deliver") {
				return finish("stopped", "recovered_without_delivery")
			}
		}
		return uncertain()
	}
	review, live, err := s.source(ctx, tx, r.Scope, r.DeviceID, r.Groups, r.ExtraDNS)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrRefreshNotReady) || errors.Is(err, ErrManualUnsupported) || errors.Is(err, ErrNetbirdOperationChanged) || errors.Is(err, ErrNetbirdOperationNotReady) {
		return stop("source_changed")
	}
	if err != nil {
		return true, err
	}
	if review.Revision != r.Revision || live.Base != snapshot.Base || live.Token != snapshot.Token || live.Identity != snapshot.Identity || !live.IdentityExpiresAt.Equal(snapshot.IdentityExpiresAt) {
		return stop("source_changed")
	}
	if !time.Now().Before(r.ExpiresAt) {
		return stop("expired")
	}
	expires := r.ExpiresAt
	if !snapshot.IdentityExpiresAt.IsZero() && snapshot.IdentityExpiresAt.Before(expires) {
		expires = snapshot.IdentityExpiresAt
	}
	if !time.Now().Add(time.Second).Before(expires) {
		return stop("expired")
	}
	policy := netbirdapi.ManagedKeyRequest{RequestID: r.ID, Groups: r.Groups, ExtraDNS: r.ExtraDNS}
	digest, err := policy.Digest()
	if err != nil {
		return stop("source_changed")
	}
	if err = s.attempt(ctx, r, "create", digest); err != nil {
		return true, err
	}
	create, cancelCreate := context.WithDeadline(ctx, expires)
	bounded, cancelBounded := context.WithTimeout(create, 5*time.Second)
	key, err := netbirdapi.CreateManagedKey(bounded, s.transport, snapshot.Base, snapshot.Token, policy)
	createErr := bounded.Err()
	cancelBounded()
	cancelCreate()
	if err != nil || createErr != nil || key == nil {
		return uncertain()
	}
	plain := []byte(key.Secret)
	sealed, err := sealRegistration(s.cipher, r, "setup-key", key.ID, plain)
	clear(plain)
	if err != nil {
		return true, err
	}
	if err = s.evidence(ctx, r, "key", key.ManagedKeyMetadata, sealed); err != nil {
		return true, err
	}
	r.Key = &key.ManagedKeyMetadata
	command := netbirdcommand.Command{Version: netbirdcommand.RegistrationVersion, Identity: snapshot.Identity, RequestID: r.ID, Revision: r.Revision, Operation: "register", ManagementURL: snapshot.Base, SetupKey: key.Secret, IssuedAt: r.RequestedAt, ExpiresAt: expires}
	key.Secret = ""
	digest, err = command.Digest()
	if err == nil && time.Now().Before(expires) {
		if err = s.attempt(ctx, r, "deliver", digest); err != nil {
			return true, err
		}
		call, cancelCall := context.WithDeadline(ctx, expires)
		var result *NetbirdOperationResult
		if call.Err() == nil {
			result, err = s.operations.execute(call, command)
		} else {
			err = call.Err()
		}
		command.SetupKey = ""
		callErr := call.Err()
		cancelCall()
		if err == nil && callErr == nil && result != nil && result.Success && result.RequestID == r.ID && result.DeviceID == r.DeviceID && result.Revision == r.Revision && result.Operation == "register" && result.CommandHash == digest {
			if err = s.evidence(ctx, r, "delivered", result, ""); err != nil {
				return true, err
			}
			r.Delivered = result
		}
	}
	_ = s.cleanup(ctx, r, snapshot)
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	if r.KeyAbsent {
		if r.Delivered != nil {
			return finish("completed", "")
		}
		if !slices.Contains(r.Attempts, "deliver") {
			return finish("stopped", "expired")
		}
	}
	return uncertain()
}
