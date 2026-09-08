package apple

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"howett.net/plist"
)

type recoveryLockFixture struct {
	s     *Store
	d     *Device
	scope Scope
}
type recoveryLockWire struct {
	ID      string `plist:"CommandUUID"`
	Command map[string]any
}

func newRecoveryLockFixture(t *testing.T) *recoveryLockFixture {
	t.Helper()
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, cert, _ := testEnrollOptionsWithKey(t, s, scope, "Recovery Lock synthetic Mac", "Mac16,1", "15.0", EnrollmentOptions{AllowMacDeviceLock: true})
	drainMacInventory(t, s, d)
	d, err := s.AuthenticateCertificate(t.Context(), d.ID, cert)
	if err != nil {
		t.Fatal(err)
	}
	if reason := d.RecoveryLockReason(time.Now()); reason != "" {
		t.Fatal(reason)
	}
	return &recoveryLockFixture{s, d, scope}
}

func (f *recoveryLockFixture) state(t *testing.T) *RecoveryLock {
	t.Helper()
	r, err := f.s.RecoveryLock(t.Context(), f.scope, f.d.ID)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *recoveryLockFixture) request(t *testing.T, operation, key string, password []byte) {
	t.Helper()
	if err := f.s.requestRecoveryLock(t.Context(), f.scope, f.d.ID, operation, key, password, "admin", nil); err != nil {
		t.Fatal(operation, err)
	}
}

func (f *recoveryLockFixture) connect(t *testing.T, status, id string, fields map[string]any) *recoveryLockWire {
	t.Helper()
	m := map[string]any{"UDID": f.d.UDID, "Status": status, "CommandUUID": id}
	for k, v := range fields {
		m[k] = v
	}
	payload, err := f.s.Connect(t.Context(), f.d, m)
	if err != nil {
		t.Fatal("synthetic native connection", err)
	}
	defer clear(payload)
	if len(payload) == 0 {
		return nil
	}
	var wire recoveryLockWire
	if _, err = plist.Unmarshal(payload, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Command["RequestType"] != "SetRecoveryLock" && wire.Command["RequestType"] != "VerifyRecoveryLock" {
		t.Fatal("unexpected command", wire.Command["RequestType"])
	}
	return &wire
}

func requireRecoveryLockWire(t *testing.T, w *recoveryLockWire, kind string) {
	t.Helper()
	if w == nil || w.Command["RequestType"] != kind {
		t.Fatal("missing expected command", kind)
	}
}

func (f *recoveryLockFixture) establish(t *testing.T) string {
	t.Helper()
	f.request(t, "set", "", nil)
	set := f.connect(t, "Idle", "", nil)
	requireRecoveryLockWire(t, set, "SetRecoveryLock")
	verify := f.connect(t, "Acknowledged", set.ID, nil)
	requireRecoveryLockWire(t, verify, "VerifyRecoveryLock")
	if verify.Command["Password"] != set.Command["NewPassword"] {
		t.Fatal("wrong proposed password verified")
	}
	if f.connect(t, "Acknowledged", verify.ID, map[string]any{"PasswordVerified": true}) != nil {
		t.Fatal("extra command after verified set")
	}
	r := f.state(t)
	if r.Evidence != "verified" || r.Attempt.Status != "verified" || r.CurrentKeyID != r.Attempt.CandidateKeyID {
		t.Fatal("password not promoted after verification")
	}
	return r.CurrentKeyID
}

func TestRecoveryLockNativeSetRotateRemoveRetainsEncryptedHistory(t *testing.T) {
	f := newRecoveryLockFixture(t)
	first := f.establish(t)
	old, err := f.s.revealRecoveryLockPassword(t.Context(), f.scope, f.d.ID, first, "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(old)
	f.request(t, "rotate", first, nil)
	check := f.connect(t, "Idle", "", nil)
	requireRecoveryLockWire(t, check, "VerifyRecoveryLock")
	if check.Command["Password"] != string(old) {
		t.Fatal("rotation skipped current password")
	}
	set := f.connect(t, "Acknowledged", check.ID, map[string]any{"PasswordVerified": true})
	requireRecoveryLockWire(t, set, "SetRecoveryLock")
	if set.Command["CurrentPassword"] != string(old) || set.Command["NewPassword"] == string(old) {
		t.Fatal("rotation used wrong passwords")
	}
	verify := f.connect(t, "Acknowledged", set.ID, nil)
	requireRecoveryLockWire(t, verify, "VerifyRecoveryLock")
	if verify.Command["Password"] != set.Command["NewPassword"] {
		t.Fatal("rotation checked old password")
	}
	if f.state(t).CurrentKeyID != first {
		t.Fatal("acknowledgment prematurely promoted password")
	}
	f.connect(t, "Acknowledged", verify.ID, map[string]any{"PasswordVerified": true})
	second := f.state(t).CurrentKeyID
	if second == first {
		t.Fatal("rotation did not promote new password")
	}
	f.request(t, "remove", second, nil)
	check = f.connect(t, "Idle", "", nil)
	requireRecoveryLockWire(t, check, "VerifyRecoveryLock")
	set = f.connect(t, "Acknowledged", check.ID, map[string]any{"PasswordVerified": true})
	requireRecoveryLockWire(t, set, "SetRecoveryLock")
	if set.Command["NewPassword"] != "" || set.Command["CurrentPassword"] != check.Command["Password"] {
		t.Fatal("incorrect removal payload")
	}
	f.connect(t, "Acknowledged", set.ID, nil)
	r := f.state(t)
	if r.CurrentKeyID != "" || r.Evidence != "removal_acknowledged" || r.Attempt.Status != "removed" {
		t.Fatal("removal not recorded accurately")
	}
	keys, err := f.s.RecoveryLockKeys(t.Context(), f.scope, f.d.ID)
	if err != nil || len(keys) != 2 {
		t.Fatal("password history discarded", err)
	}
	for _, key := range keys {
		if key.Current || key.VerifiedAt == nil {
			t.Fatal("incorrect retained password metadata")
		}
		plain, e := f.s.revealRecoveryLockPassword(t.Context(), f.scope, f.d.ID, key.ID, "admin", nil)
		if e != nil {
			t.Fatal(e)
		}
		var encrypted []byte
		if e = f.s.db.QueryRow(`SELECT password FROM mdm_apple_recovery_lock_keys WHERE id=$1`, key.ID).Scan(&encrypted); e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(encrypted, plain) {
			t.Fatal("plaintext stored in key history")
		}
		if _, e = f.s.secrets.open(encrypted, secretPurpose(f.d.TenantID, f.d.ID+"/"+uuid.NewString(), "recovery_lock_password")); e == nil {
			t.Fatal("ciphertext transplanted between keys")
		}
		metadata, _ := json.Marshal(struct {
			State *RecoveryLock
			Keys  []RecoveryLockKey
		}{r, keys})
		if bytes.Contains(metadata, plain) {
			t.Fatal("password leaked into metadata")
		}
		clear(plain)
	}
	var clean bool
	if err = f.s.db.QueryRow(`SELECT bool_and(octet_length(payload)=0) FROM mdm_apple_commands WHERE recovery_lock`).Scan(&clean); err != nil || !clean {
		t.Fatal("completed commands retained sensitive payloads", err)
	}
	var count int
	if err = f.s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE action LIKE 'apple.recovery_lock.%' AND details->>'site_id'='1'`).Scan(&count); err != nil || count < 12 {
		t.Fatal("scoped Recovery Lock audit missing", count, err)
	}
}

func TestRecoveryLockMutationIsDeliveredOnceAndCannotUseOldProofWhileUnresolved(t *testing.T) {
	f := newRecoveryLockFixture(t)
	first := f.establish(t)
	f.request(t, "rotate", first, nil)
	check := f.connect(t, "Idle", "", nil)
	set := f.connect(t, "Acknowledged", check.ID, map[string]any{"PasswordVerified": true})
	requireRecoveryLockWire(t, set, "SetRecoveryLock")
	// Lose the mutation response. The next poll may only check its new password.
	verify := f.connect(t, "Idle", "", nil)
	requireRecoveryLockWire(t, verify, "VerifyRecoveryLock")
	f.connect(t, "Acknowledged", verify.ID, map[string]any{"PasswordVerified": false})
	r := f.state(t)
	if r.Attempt.Status != "uncertain" || r.Attempt.CanCheckPrevious {
		t.Fatal("negative check released an unresolved mutation")
	}
	for _, op := range []string{"rotate", "remove", "verify", "import"} {
		var password []byte
		if op == "import" {
			password = []byte("synthetic-existing-password")
		}
		if err := f.s.requestRecoveryLock(t.Context(), f.scope, f.d.ID, op, first, password, "admin", nil); !errors.Is(err, ErrConflict) {
			t.Fatal("overlapping operation accepted", op, err)
		}
	}
	if err := f.s.requestRecoveryLock(t.Context(), f.scope, f.d.ID, "recheck", first, nil, "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("old password used without mutation stopping proof", err)
	}
	if err := f.s.RetryCommand(t.Context(), f.scope, f.d.ID, set.ID, "admin"); err == nil {
		t.Fatal("generic mutation retry accepted")
	}
	for _, statement := range []string{
		`UPDATE mdm_apple_commands SET attempts=attempts+1 WHERE id=$1`,
		`UPDATE mdm_apple_commands SET status='queued' WHERE id=$1`,
		`UPDATE mdm_apple_commands SET payload='\x01' WHERE id=$1`,
		`UPDATE mdm_apple_commands SET recovery_lock=false,request_type='SecurityInfo' WHERE id=$1`,
	} {
		if _, err := f.s.db.Exec(statement, set.ID); err == nil {
			t.Fatal("mutation delivery guard bypassed")
		}
	}
	// A late acknowledgment supplies stopping proof; it does not verify a password.
	f.connect(t, "Acknowledged", set.ID, nil)
	if r = f.state(t); !r.Attempt.CanCheckPrevious || r.Attempt.Status != "uncertain" {
		t.Fatal("late acknowledgment lost or treated as password proof")
	}
	f.request(t, "recheck", first, nil)
	previous := f.connect(t, "Idle", "", nil)
	requireRecoveryLockWire(t, previous, "VerifyRecoveryLock")
	f.connect(t, "Acknowledged", previous.ID, map[string]any{"PasswordVerified": true})
	if r = f.state(t); r.Attempt.Status != "resolved" || r.CurrentKeyID != first {
		t.Fatal("verified previous password did not resolve stopped mutation")
	}
	var attempts int
	if err := f.s.db.QueryRow(`SELECT attempts FROM mdm_apple_commands WHERE id=$1`, set.ID).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatal("mutation repeated", attempts, err)
	}
}

func TestRecoveryLockLostAcknowledgmentCanResolveWithDistinctCandidate(t *testing.T) {
	f := newRecoveryLockFixture(t)
	f.request(t, "set", "", nil)
	set := f.connect(t, "Idle", "", nil)
	if next := f.connect(t, "NotNow", set.ID, nil); next != nil {
		t.Fatal("NotNow did not stop delivery")
	}
	verify := f.connect(t, "Idle", "", nil)
	requireRecoveryLockWire(t, verify, "VerifyRecoveryLock")
	if verify.Command["Password"] != set.Command["NewPassword"] {
		t.Fatal("wrong distinct candidate checked")
	}
	f.connect(t, "Acknowledged", verify.ID, map[string]any{"PasswordVerified": true})
	before := f.state(t)
	if before.Attempt.Status != "verified" {
		t.Fatal("new password proof did not resolve missing acknowledgment")
	}
	f.connect(t, "Error", set.ID, map[string]any{"ErrorChain": []any{map[string]any{"LocalizedDescription": set.Command["NewPassword"]}}})
	after := f.state(t)
	if before.CurrentKeyID != after.CurrentKeyID || after.Attempt.Status != "verified" {
		t.Fatal("late contradictory response changed completed result")
	}
}

func TestRecoveryLockVerificationRequiresStrictBooleanAndDoesNotLeakDeviceErrors(t *testing.T) {
	for name, fields := range map[string]map[string]any{
		"missing": {}, "string": {"PasswordVerified": "true"}, "false": {"PasswordVerified": false},
		"error": {"ErrorChain": []any{map[string]any{"LocalizedDescription": "synthetic-secret-must-not-leak"}}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRecoveryLockFixture(t)
			f.request(t, "import", "", []byte("synthetic-secret-must-not-leak"))
			verify := f.connect(t, "Idle", "", nil)
			requireRecoveryLockWire(t, verify, "VerifyRecoveryLock")
			status := "Acknowledged"
			if name == "error" {
				status = "Error"
			}
			if f.connect(t, status, verify.ID, fields) != nil {
				t.Fatal("failed import produced mutation")
			}
			r := f.state(t)
			if r.CurrentKeyID != "" || r.Attempt.Status != "failed" {
				t.Fatal("unverified import promoted")
			}
			var leaked bool
			if err := f.s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM mdm_apple_audit WHERE row_to_json(mdm_apple_audit)::text LIKE '%synthetic-secret-must-not-leak%') OR EXISTS(SELECT 1 FROM mdm_apple_commands WHERE error LIKE '%synthetic-secret-must-not-leak%') OR EXISTS(SELECT 1 FROM mdm_apple_recovery_lock_attempts WHERE error LIKE '%synthetic-secret-must-not-leak%')`).Scan(&leaked); err != nil || leaked {
				t.Fatal("sensitive result persisted", err)
			}
		})
	}
}

func TestRecoveryLockExpiredPreflightCannotAuthorizeChange(t *testing.T) {
	f := newRecoveryLockFixture(t)
	key := f.establish(t)
	f.request(t, "rotate", key, nil)
	check := f.connect(t, "Idle", "", nil)
	if _, err := f.s.db.Exec(`UPDATE mdm_apple_commands SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, check.ID); err != nil {
		t.Fatal(err)
	}
	if f.connect(t, "Acknowledged", check.ID, map[string]any{"PasswordVerified": true}) != nil {
		t.Fatal("expired preflight authorized mutation")
	}
	r := f.state(t)
	if r.Attempt.Status != "failed" || r.Attempt.Error != "current_password_check_expired" || r.CurrentKeyID != key {
		t.Fatal("wrong expired preflight outcome")
	}
	var count int
	if err := f.s.db.QueryRow(`SELECT count(*) FROM mdm_apple_recovery_lock_commands WHERE attempt_id=$1 AND purpose='set'`, r.Attempt.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired preflight queued mutation", err)
	}
}

func TestRecoveryLockLateAndSupersededChecksCannotRefreshEvidence(t *testing.T) {
	f := newRecoveryLockFixture(t)
	f.request(t, "set", "", nil)
	set := f.connect(t, "Idle", "", nil)
	verify := f.connect(t, "Acknowledged", set.ID, nil)
	if _, err := f.s.db.Exec(`UPDATE mdm_apple_commands SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, verify.ID); err != nil {
		t.Fatal(err)
	}
	f.connect(t, "Idle", "", nil)
	r := f.state(t)
	if r.Attempt.Status != "uncertain" {
		t.Fatal("expired candidate not uncertain")
	}
	f.request(t, "recheck", r.Attempt.CandidateKeyID, nil)
	newer := f.connect(t, "Idle", "", nil)
	f.connect(t, "Acknowledged", verify.ID, map[string]any{"PasswordVerified": true})
	if f.state(t).CurrentKeyID != "" {
		t.Fatal("superseded check promoted password")
	}
	// Conservative observation time comes from dispatch, not receipt arrival.
	if _, err := f.s.db.Exec(`UPDATE mdm_apple_recovery_lock_commands SET dispatched_at=clock_timestamp()-interval '2 days' WHERE command_id=$1`, newer.ID); err != nil {
		t.Fatal(err)
	}
	f.connect(t, "Acknowledged", newer.ID, map[string]any{"PasswordVerified": true})
	keys, err := f.s.RecoveryLockKeys(t.Context(), f.scope, f.d.ID)
	if err != nil || len(keys) != 1 || keys[0].VerifiedAt == nil || keys[0].VerifiedAt.After(time.Now().Add(-47*time.Hour)) {
		t.Fatal("late check presented as fresh", err)
	}
	before := *keys[0].VerifiedAt
	f.connect(t, "Acknowledged", newer.ID, map[string]any{"PasswordVerified": true})
	keys, err = f.s.RecoveryLockKeys(t.Context(), f.scope, f.d.ID)
	if err != nil || !keys[0].VerifiedAt.Equal(before) {
		t.Fatal("duplicate check refreshed evidence", err)
	}
}

func TestRecoveryLockRequestAndRevealAreScopedAuthorizedAndAtomic(t *testing.T) {
	f := newRecoveryLockFixture(t)
	for _, scope := range []Scope{{TenantID: 2, SiteID: 2}, {TenantID: 1, SiteID: 2}} {
		if err := f.s.requestRecoveryLock(t.Context(), scope, f.d.ID, "set", "", nil, "admin", nil); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign scope queued password change", err)
		}
	}
	if err := f.s.RequestRecoveryLock(t.Context(), f.scope, f.d.ID, "set", "", nil, "admin", nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("missing permission accepted", err)
	}
	deny := func(context.Context, *sql.Tx) error { return access.ErrDenied }
	if err := f.s.requestRecoveryLock(t.Context(), f.scope, f.d.ID, "set", "", nil, "admin", deny); !errors.Is(err, access.ErrDenied) {
		t.Fatal("denied authorization accepted", err)
	}
	if _, err := f.s.db.Exec(`ALTER TABLE mdm_apple_audit ADD CONSTRAINT recovery_lock_test_rollback CHECK(action<>'apple.recovery_lock.set')`); err != nil {
		t.Fatal(err)
	}
	if err := f.s.requestRecoveryLock(t.Context(), f.scope, f.d.ID, "set", "", nil, "admin", nil); err == nil {
		t.Fatal("audit failure accepted")
	}
	var clean bool
	if err := f.s.db.QueryRow(`SELECT NOT EXISTS(SELECT 1 FROM mdm_apple_recovery_lock_keys) AND NOT EXISTS(SELECT 1 FROM mdm_apple_recovery_lock_attempts) AND NOT EXISTS(SELECT 1 FROM mdm_apple_commands WHERE recovery_lock)`).Scan(&clean); err != nil || !clean {
		t.Fatal("failed request retained secret or command", err)
	}
	if _, err := f.s.db.Exec(`ALTER TABLE mdm_apple_audit DROP CONSTRAINT recovery_lock_test_rollback`); err != nil {
		t.Fatal(err)
	}
	key := f.establish(t)
	if password, err := f.s.RevealRecoveryLockPassword(t.Context(), f.scope, f.d.ID, key, "admin", nil); !errors.Is(err, access.ErrDenied) || len(password) > 0 {
		t.Fatal("missing permission disclosed password", err)
	}
	for _, scope := range []Scope{{TenantID: 2, SiteID: 2}, {TenantID: 1, SiteID: 2}} {
		if password, err := f.s.revealRecoveryLockPassword(t.Context(), scope, f.d.ID, key, "admin", nil); !errors.Is(err, ErrNotFound) || len(password) > 0 {
			t.Fatal("foreign scope disclosed password", err)
		}
		if _, err := f.s.RecoveryLockKeys(t.Context(), scope, f.d.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign scope disclosed metadata", err)
		}
	}
	if _, err := f.s.db.Exec(`ALTER TABLE mdm_apple_audit ADD CONSTRAINT recovery_lock_test_rollback CHECK(action<>'apple.recovery_lock.password.reveal')`); err != nil {
		t.Fatal(err)
	}
	if password, err := f.s.revealRecoveryLockPassword(t.Context(), f.scope, f.d.ID, key, "admin", nil); err == nil || len(password) > 0 {
		t.Fatal("audit failure disclosed password")
	}
}

func TestRecoveryLockConcurrentRequestsAndPollsDeliverOneMutation(t *testing.T) {
	f := newRecoveryLockFixture(t)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() { results <- f.s.requestRecoveryLock(t.Context(), f.scope, f.d.ID, "set", "", nil, "admin", nil) })
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("concurrent requests were not serialized", success, conflict)
	}
	var mu sync.Mutex
	kinds := map[string]int{}
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			payload, err := f.s.Connect(t.Context(), f.d, map[string]any{"Status": "Idle", "UDID": f.d.UDID})
			defer clear(payload)
			if err != nil {
				errs <- err
				return
			}
			var wire recoveryLockWire
			if _, err = plist.Unmarshal(payload, &wire); err != nil {
				errs <- err
				return
			}
			mu.Lock()
			kinds[wire.Command["RequestType"].(string)]++
			mu.Unlock()
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if kinds["SetRecoveryLock"] != 1 || kinds["VerifyRecoveryLock"] != 1 {
		t.Fatal("concurrent polls repeated mutation", kinds)
	}
}

func TestRecoveryLockRevocationRetainsPasswordsAndScrubsCommands(t *testing.T) {
	f := newRecoveryLockFixture(t)
	key := f.establish(t)
	f.request(t, "rotate", key, nil)
	if err := f.s.RevokeEnrollment(t.Context(), f.scope, f.d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	r := f.state(t)
	if r.Attempt.Status != "cancelled" || r.Attempt.Error != "enrollment_ended" || r.CurrentKeyID != key {
		t.Fatal("revocation lost password history or pending cancellation")
	}
	var clean bool
	if err := f.s.db.QueryRow(`SELECT bool_and(octet_length(payload)=0 AND status NOT IN ('queued','sent','not_now')) FROM mdm_apple_commands WHERE recovery_lock`).Scan(&clean); err != nil || !clean {
		t.Fatal("revocation retained command credentials", err)
	}
	plain, err := f.s.revealRecoveryLockPassword(t.Context(), f.scope, f.d.ID, key, "admin", nil)
	if err != nil || len(plain) == 0 {
		t.Fatal("revocation discarded protected recovery access", err)
	}
	clear(plain)
	if _, err = f.s.Connect(t.Context(), f.d, map[string]any{"UDID": f.d.UDID, "Status": "Idle"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked identity received work", err)
	}
}

func TestRecoveryLockReadinessChangesAndDeliveryRollback(t *testing.T) {
	for _, tc := range []struct{ name, statement string }{
		{"stale security", `UPDATE mdm_apple_devices SET security_at=clock_timestamp()-interval '25 hours' WHERE id=$1`},
		{"unknown silicon", `UPDATE mdm_apple_devices SET apple_silicon=NULL WHERE id=$1`},
		{"short certificate", `UPDATE mdm_apple_devices SET certificate_expires_at=clock_timestamp()+interval '30 seconds' WHERE id=$1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRecoveryLockFixture(t)
			f.request(t, "set", "", nil)
			if _, err := f.s.db.Exec(tc.statement, f.d.ID); err != nil {
				t.Fatal(err)
			}
			if f.connect(t, "Idle", "", nil) != nil {
				t.Fatal("readiness change did not stop queued mutation")
			}
			if f.state(t).Attempt.Status != "failed" {
				t.Fatal("undelivered mutation wrongly remained active")
			}
		})
	}
	f := newRecoveryLockFixture(t)
	f.request(t, "set", "", nil)
	if _, err := f.s.db.Exec(`ALTER TABLE mdm_apple_commands ADD CONSTRAINT recovery_lock_delivery_rollback CHECK(NOT recovery_lock OR attempts=0)`); err != nil {
		t.Fatal(err)
	}
	payload, err := f.s.Connect(t.Context(), f.d, map[string]any{"UDID": f.d.UDID, "Status": "Idle"})
	if err == nil || len(payload) > 0 {
		t.Fatal("failed delivery transaction exposed command")
	}
	var intact bool
	if err = f.s.db.QueryRow(`SELECT c.attempts=0 AND octet_length(c.payload)>28 AND r.dispatched_at IS NULL FROM mdm_apple_commands c JOIN mdm_apple_recovery_lock_commands r ON r.command_id=c.id WHERE c.recovery_lock`).Scan(&intact); err != nil || !intact {
		t.Fatal("failed delivery consumed password command", err)
	}
	if _, err = f.s.db.Exec(`ALTER TABLE mdm_apple_commands DROP CONSTRAINT recovery_lock_delivery_rollback`); err != nil {
		t.Fatal(err)
	}
	requireRecoveryLockWire(t, f.connect(t, "Idle", "", nil), "SetRecoveryLock")
}
