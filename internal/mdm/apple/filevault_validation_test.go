package apple

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type validationFixture struct {
	s         *Store
	d         *Device
	scope     Scope
	registry  *registry.Store
	access    *registry.AccessStore
	identity  *registry.Identity
	keys      *enrollment.Keys
	cert      *x509.Certificate
	recipient *enrollment.RecoveryRecipient
	private   *enrollment.RecoveryRecipientKey
	keyID     string
}

func newValidationFixture(t *testing.T) *validationFixture {
	t.Helper()
	s, d, r := macBindingFixture(t)
	f := &validationFixture{s: s, d: d, scope: Scope{TenantID: d.TenantID, SiteID: d.SiteID}, registry: r}
	if _, err := r.EnsureAuthority(t.Context(), d.TenantID, "Validation fixture", "https://uem.example.test", "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	in, err := r.Invite(t.Context(), registry.InvitationOptions{Scope: registry.Scope{TenantID: d.TenantID, SiteID: d.SiteID}, Platform: "macos", Architecture: "arm64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	f.keys, err = enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.keys.Broker.Wipe)
	request, err := f.keys.Request(in.URL[strings.LastIndex(in.URL, "/")+1:], "macos", "arm64", "Validation Mac")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := r.Claim(t.Context(), *request)
	if err != nil {
		t.Fatal(err)
	}
	f.access, err = registry.NewAccessStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	f.identity, err = f.access.ActiveIdentity(t.Context(), issued.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(issued.Certificate))
	if block == nil {
		t.Fatal("missing fixture certificate")
	}
	f.cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TABLE agents(oid TEXT PRIMARY KEY); CREATE TABLE site_agents(agent_id TEXT NOT NULL REFERENCES agents(oid),site_id BIGINT NOT NULL REFERENCES sites(id),PRIMARY KEY(agent_id,site_id))`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO agents VALUES($1)`, issued.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO site_agents VALUES($1,$2)`, issued.DeviceID, d.SiteID); err != nil {
		t.Fatal(err)
	}
	proof := deliverMacProof(t, s, d)
	recordMacProof(t, s, f.identity, proof)
	if err = s.ReconcileMacLinks(t.Context()); err != nil {
		t.Fatal(err)
	}
	acknowledgeMacCleanup(t, s, d)
	testActivateFileVault(t, s, d, f.scope)
	var der []byte
	if err = s.db.QueryRow(`SELECT certificate FROM mdm_apple_filevault_escrow WHERE device_id=$1`, d.ID).Scan(&der); err != nil {
		t.Fatal(err)
	}
	escrow, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	testFileVaultSecurity(t, s, d, map[string]any{"FDE_Enabled": true, "FDE_HasPersonalRecoveryKey": true, "FDE_PersonalRecoveryKeyDeviceKey": d.ID, "FDE_PersonalRecoveryKeyCMS": testFileVaultEnvelope(t, escrow, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), fileVaultAES256OID, false)})
	if err = s.db.QueryRow(`SELECT current_key_id FROM mdm_apple_filevault_policies WHERE device_id=$1`, d.ID).Scan(&f.keyID); err != nil {
		t.Fatal(err)
	}
	f.private, err = enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.private.Close)
	f.register(t, f.private)
	return f
}

func (f *validationFixture) register(t *testing.T, key *enrollment.RecoveryRecipientKey) {
	t.Helper()
	reply, err := f.access.HandleRecovery(t.Context(), *f.identity, enrollment.RecoveryRequest{Version: 1, AgentID: f.identity.ID, Action: "challenge", PublicKey: key.PublicKey()})
	if err != nil || reply.Registration == nil {
		t.Fatal("challenge failed", err)
	}
	signature, err := enrollment.SignRecoveryRegistration(*reply.Registration, f.cert, f.keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	reply, err = f.access.HandleRecovery(t.Context(), *f.identity, enrollment.RecoveryRequest{Version: 1, AgentID: f.identity.ID, Action: "register", Registration: reply.Registration, Signature: signature})
	if err != nil || reply.Recipient == nil {
		t.Fatal("registration failed", err)
	}
	f.recipient = reply.Recipient
}

func (f *validationFixture) queue(t *testing.T) string {
	t.Helper()
	if err := f.s.requestFileVaultValidation(t.Context(), f.scope, f.d.ID, f.keyID, "admin", nil); err != nil {
		t.Fatal("queue failed", err)
	}
	var id string
	if err := f.s.db.QueryRow(`SELECT id FROM mdm_apple_filevault_validations WHERE device_id=$1 AND status='queued'`, f.d.ID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *validationFixture) report(t *testing.T, outcome string) *enrollment.RecoveryTask {
	t.Helper()
	reply, err := f.access.HandleRecovery(t.Context(), *f.identity, enrollment.RecoveryRequest{Version: 1, AgentID: f.identity.ID, Action: "poll", RecipientID: f.recipient.ID})
	if err != nil || reply.Task == nil {
		t.Fatal("private poll failed", err)
	}
	secret, err := f.private.Open(*reply.Task, f.recipient.Identity, f.recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret.Key(), []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) {
		t.Fatal("wrong escrow key sent to agent")
	}
	result, err := secret.Result(outcome, f.cert, f.keys.Certificate, time.Now())
	secret.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.access.HandleRecovery(t.Context(), *f.identity, enrollment.RecoveryRequest{Version: 1, AgentID: f.identity.ID, Action: "result", Result: result}); err != nil {
		t.Fatal("signed result failed", err)
	}
	return reply.Task
}

func (f *validationFixture) reconcile(t *testing.T) {
	t.Helper()
	if _, err := f.s.db.Exec(`UPDATE mdm_apple_filevault_validations SET next_check_at=clock_timestamp() WHERE device_id=$1`, f.d.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.s.ReconcileFileVaultValidations(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestFileVaultValidationCompletesPrivateRoundTripAndPreservesHistory(t *testing.T) {
	f := newValidationFixture(t)
	v, err := f.s.FileVault(t.Context(), f.scope, f.d.ID)
	if err != nil || !v.ValidationReady || v.Validation != nil || v.VerifiedAt != nil {
		t.Fatal("invalid initial validation state", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 3)
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- f.s.requestFileVaultValidation(t.Context(), f.scope, f.d.ID, f.keyID, "admin", nil)
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err = f.s.db.QueryRow(`SELECT count(*) FROM mdm_apple_filevault_validations`).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate requests produced different tasks", count, err)
	}
	var stored []byte
	if err = f.s.db.QueryRow(`SELECT envelope FROM uem_agent_recovery_tasks`).Scan(&stored); err != nil || bytes.Contains(stored, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) {
		t.Fatal("routing storage exposed plaintext", err)
	}
	f.report(t, "valid")
	v, err = f.s.FileVault(t.Context(), f.scope, f.d.ID)
	if err != nil || v.VerifiedAt != nil || v.Validation.Status != "queued" {
		t.Fatal("worker bypassed console verification", err)
	}
	f.reconcile(t)
	v, err = f.s.FileVault(t.Context(), f.scope, f.d.ID)
	if err != nil || v.Validation.Status != "valid" || v.VerifiedAt == nil {
		t.Fatal("valid result not reconciled", err)
	}
	verified := *v.VerifiedAt
	f.reconcile(t)
	if err = f.s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE action='apple.filevault.validation.valid' AND details->>'site_id'='1'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate processing changed audit", err)
	}
	for _, outcome := range []string{"invalid", "unavailable", "unsupported"} {
		f.queue(t)
		f.report(t, outcome)
		f.reconcile(t)
		v, err = f.s.FileVault(t.Context(), f.scope, f.d.ID)
		if err != nil || v.Validation.Status != outcome || v.VerifiedAt == nil || !v.VerifiedAt.Equal(verified) {
			t.Fatal("negative result erased or invented historical success", outcome, err)
		}
	}
}

func TestFileVaultValidationRejectsAlteredReceiptsIndependently(t *testing.T) {
	for _, scenario := range []string{"outcome", "nonce", "key", "unknown_field", "missing_delivery", "late_result"} {
		t.Run(scenario, func(t *testing.T) {
			f := newValidationFixture(t)
			id := f.queue(t)
			task := f.report(t, "invalid")
			var data []byte
			if err := f.s.db.QueryRow(`SELECT result FROM uem_agent_recovery_tasks WHERE id=$1`, id).Scan(&data); err != nil {
				t.Fatal(err)
			}
			var result enrollment.RecoveryResult
			if json.Unmarshal(data, &result) != nil {
				t.Fatal("bad fixture receipt")
			}
			switch scenario {
			case "outcome":
				result.Outcome = "valid"
				data, _ = json.Marshal(result)
			case "nonce", "key":
				c := task.Context
				nonce := bytes.Repeat([]byte{8}, 32)
				if scenario == "key" {
					c.KeyID = uuid.NewString()
					nonce = result.Nonce
				}
				changed, err := enrollment.EncryptRecoveryTask(*f.recipient, c, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), nonce, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				secret, err := f.private.Open(*changed, c.Identity, c.RecipientID, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				proof, err := secret.Result("valid", f.cert, f.keys.Certificate, time.Now())
				secret.Close()
				if err != nil {
					t.Fatal(err)
				}
				data, _ = json.Marshal(proof)
			case "unknown_field":
				data = append(data[:len(data)-1], []byte(`,"unexpected":true}`)...)
			case "missing_delivery":
				if _, err := f.s.db.Exec(`UPDATE uem_agent_recovery_tasks SET delivered_at=NULL WHERE id=$1`, id); err != nil {
					t.Fatal(err)
				}
			case "late_result":
				if _, err := f.s.db.Exec(`UPDATE uem_agent_recovery_tasks SET completed_at=expires_at+interval '1 second' WHERE id=$1`, id); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.s.db.Exec(`UPDATE uem_agent_recovery_tasks SET result=$2 WHERE id=$1`, id, data); err != nil {
				t.Fatal(err)
			}
			f.reconcile(t)
			v, err := f.s.FileVault(t.Context(), f.scope, f.d.ID)
			if err != nil || v.VerifiedAt != nil || v.Validation.Status != "rejected" {
				t.Fatal("altered receipt validated key", scenario, err)
			}
		})
	}
}

func TestFileVaultValidationCancelsChangedAuthorityAndPreservesKeys(t *testing.T) {
	for _, scenario := range []string{"agent_revocation", "agent_revocation_after_report", "agent_expiry", "native_revocation", "retired_channel_after_report", "recipient_replacement", "hardware_drift", "inventory_scope", "site_owner", "expired_task", "new_key"} {
		t.Run(scenario, func(t *testing.T) {
			f := newValidationFixture(t)
			id := f.queue(t)
			want := "cancelled"
			var err error
			switch scenario {
			case "agent_revocation":
				err = f.registry.RevokeIdentity(t.Context(), f.identity.Scope, f.identity.ID, "admin")
			case "agent_revocation_after_report":
				f.report(t, "valid")
				err = f.registry.RevokeIdentity(t.Context(), f.identity.Scope, f.identity.ID, "admin")
			case "agent_expiry":
				_, err = f.s.db.Exec(`UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.identity.ID)
			case "retired_channel_after_report":
				f.report(t, "valid")
				_, err = f.s.db.Exec(`UPDATE uem_mac_agent_channels SET retired_at=clock_timestamp() WHERE device_id=$1`, f.identity.ID)
			case "native_revocation":
				err = f.s.RevokeEnrollment(t.Context(), f.scope, f.d.ID, "admin")
			case "recipient_replacement":
				key, e := enrollment.NewRecoveryRecipientKey()
				if e != nil {
					t.Fatal(e)
				}
				defer key.Close()
				f.register(t, key)
			case "hardware_drift":
				_, err = f.s.db.Exec(`UPDATE uem_agent_hardware SET platform_uuid=$2 WHERE device_id=$1`, f.identity.ID, strings.ToUpper(uuid.NewString()))
			case "inventory_scope":
				_, err = f.s.db.Exec(`UPDATE site_agents SET site_id=2 WHERE agent_id=$1`, f.identity.ID)
			case "site_owner":
				_, err = f.s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`)
			case "expired_task":
				want = "expired"
				_, err = f.s.db.Exec(`UPDATE mdm_apple_filevault_validations SET expires_at=date_trunc('second',clock_timestamp()-interval '1 minute') WHERE id=$1`, id)
				if err == nil {
					_, err = f.s.db.Exec(`UPDATE uem_agent_recovery_tasks SET expires_at=(SELECT expires_at FROM mdm_apple_filevault_validations WHERE id=$1) WHERE id=$1`, id)
				}
			case "new_key":
				want = "superseded"
				f.report(t, "valid")
				newID := uuid.NewString()
				var encrypted []byte
				encrypted, err = f.s.secrets.seal([]byte("GGGG-HHHH-IIII-JJJJ-KKKK-LLLL"), secretPurpose(1, f.d.ID+"/"+newID, "filevault_recovery_key"))
				if err == nil {
					_, err = f.s.db.Exec(`INSERT INTO mdm_apple_filevault_keys(id,tenant_id,device_id,escrow_id,recovery_key) SELECT $1,tenant_id,device_id,escrow_id,$2 FROM mdm_apple_filevault_keys WHERE id=$3`, newID, encrypted, f.keyID)
				}
				if err == nil {
					_, err = f.s.db.Exec(`UPDATE mdm_apple_filevault_policies SET current_key_id=$2 WHERE device_id=$1`, f.d.ID, newID)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			f.reconcile(t)
			var status string
			var verified *time.Time
			var retained int
			if err = f.s.db.QueryRow(`SELECT v.status,k.verified_at,octet_length(k.recovery_key) FROM mdm_apple_filevault_validations v JOIN mdm_apple_filevault_keys k ON k.id=v.key_id WHERE v.id=$1`, id).Scan(&status, &verified, &retained); err != nil || status != want || verified != nil || retained == 0 {
				t.Fatal("changed authority accepted or destroyed a key", status, err)
			}
			var size int
			if err = f.s.db.QueryRow(`SELECT octet_length(envelope) FROM uem_agent_recovery_tasks WHERE id=$1`, id).Scan(&size); err != nil || size != 0 {
				t.Fatal("cancelled validation retained encrypted envelope", err)
			}
		})
	}
}

func TestFileVaultValidationAuditFailureRollsBackQueueAndVerification(t *testing.T) {
	f := newValidationFixture(t)
	if _, err := f.s.db.Exec(`ALTER TABLE mdm_apple_audit ADD CONSTRAINT validation_audit_failure CHECK(action!='apple.filevault.validation.request')`); err != nil {
		t.Fatal(err)
	}
	if err := f.s.requestFileVaultValidation(t.Context(), f.scope, f.d.ID, f.keyID, "admin", nil); err == nil {
		t.Fatal("request committed without audit")
	}
	var count int
	if err := f.s.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_apple_filevault_validations)+(SELECT count(*) FROM uem_agent_recovery_tasks)`).Scan(&count); err != nil || count != 0 {
		t.Fatal("request rollback left private task", err)
	}
	if _, err := f.s.db.Exec(`ALTER TABLE mdm_apple_audit DROP CONSTRAINT validation_audit_failure`); err != nil {
		t.Fatal(err)
	}
	id := f.queue(t)
	f.report(t, "valid")
	if _, err := f.s.db.Exec(`ALTER TABLE mdm_apple_audit ADD CONSTRAINT validation_audit_failure CHECK(action!='apple.filevault.validation.valid')`); err != nil {
		t.Fatal(err)
	}
	if err := f.s.checkFileVaultValidation(t.Context(), f.scope, f.d.ID, id); err == nil {
		t.Fatal("result committed without audit")
	}
	v, err := f.s.FileVault(t.Context(), f.scope, f.d.ID)
	if err != nil || v.VerifiedAt != nil || v.Validation.Status != "queued" {
		t.Fatal("audit failure failed to roll back key status", err)
	}
	if _, err = f.s.db.Exec(`ALTER TABLE mdm_apple_audit DROP CONSTRAINT validation_audit_failure`); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t)
}

func TestFileVaultValidationRechecksRevokedConsolePermission(t *testing.T) {
	f := newValidationFixture(t)
	if _, err := f.s.db.Exec(`CREATE TABLE users(uid TEXT PRIMARY KEY); INSERT INTO users VALUES('admin'),('security-admin')`); err != nil {
		t.Fatal(err)
	}
	permissions, err := access.NewStore(f.s.db)
	if err != nil {
		t.Fatal(err)
	}
	if err = permissions.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = permissions.Bootstrap(t.Context(), "admin"); err != nil {
		t.Fatal(err)
	}
	if err = permissions.ReplaceGrants(t.Context(), "admin", "security-admin", 0, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}); err != nil {
		t.Fatal(err)
	}
	if err = f.s.RequestFileVaultValidation(t.Context(), f.scope, f.d.ID, f.keyID, "security-admin", nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("missing authorization accepted", err)
	}
	change, err := f.s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer change.Rollback()
	if _, err = change.Exec(`SELECT pg_advisory_xact_lock(684627902)`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- f.s.RequestFileVaultValidation(context.Background(), f.scope, f.d.ID, f.keyID, "security-admin", permissions)
	}()
	select {
	case err := <-done:
		t.Fatal("request bypassed authorization lock", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err = change.Exec(`DELETE FROM uem_access_grants WHERE user_id='security-admin'`); err != nil {
		t.Fatal(err)
	}
	if err = change.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, access.ErrDenied) {
			t.Fatal("revoked privilege queued a secret", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not finish")
	}
}

func TestFileVaultValidationAcceptsTimelyReceiptAfterConsoleDelay(t *testing.T) {
	f := newValidationFixture(t)
	id := f.queue(t)
	task := f.report(t, "valid")
	var encoded []byte
	if err := f.s.db.QueryRow(`SELECT result FROM uem_agent_recovery_tasks WHERE id=$1`, id).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	var original enrollment.RecoveryResult
	if json.Unmarshal(encoded, &original) != nil {
		t.Fatal("invalid fixture receipt")
	}
	created := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	expires := created.Add(time.Minute)
	completed := created.Add(30 * time.Second)
	c := task.Context
	c.ExpiresAt = expires.Unix()
	changed, err := enrollment.EncryptRecoveryTask(*f.recipient, c, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), original.Nonce, created)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := f.private.Open(*changed, c.Identity, c.RecipientID, created)
	if err != nil {
		t.Fatal(err)
	}
	result, err := secret.Result("valid", f.cert, f.keys.Certificate, completed)
	secret.Close()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.db.Exec(`UPDATE mdm_apple_filevault_validations SET created_at=$2,expires_at=$3 WHERE id=$1`, id, created, expires); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.db.Exec(`UPDATE uem_agent_recovery_tasks SET created_at=$2,delivered_at=$2,completed_at=$3,expires_at=$4,result=$5 WHERE id=$1`, id, created, completed, expires, encoded); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t)
	v, err := f.s.FileVault(t.Context(), f.scope, f.d.ID)
	if err != nil || v.Validation.Status != "valid" || v.VerifiedAt == nil || !v.VerifiedAt.Equal(completed) {
		t.Fatal("timely result lost after console delay", err)
	}
}

func TestFileVaultValidationRejectsStaleKeyAndForeignScopeBeforeQueue(t *testing.T) {
	f := newValidationFixture(t)
	for _, scope := range []Scope{{TenantID: 2}, {TenantID: 1, SiteID: 2}} {
		if err := f.s.requestFileVaultValidation(t.Context(), scope, f.d.ID, f.keyID, "admin", nil); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign validation scope accepted", err)
		}
	}
	if err := f.s.requestFileVaultValidation(t.Context(), f.scope, f.d.ID, uuid.NewString(), "admin", nil); !errors.Is(err, ErrFileVault) {
		t.Fatal("stale browser key accepted", err)
	}
	if _, err := f.s.db.Exec(`UPDATE uem_agent_hardware SET observed_at=clock_timestamp()-interval '25 hours' WHERE device_id=$1`, f.identity.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.s.requestFileVaultValidation(t.Context(), f.scope, f.d.ID, f.keyID, "admin", nil); !errors.Is(err, ErrFileVault) {
		t.Fatal("stale hardware accepted", err)
	}
	var count int
	if err := f.s.db.QueryRow(`SELECT count(*) FROM uem_agent_recovery_tasks`).Scan(&count); err != nil || count != 0 {
		t.Fatal("denied operation queued encrypted material", err)
	}
}

func TestFileVaultValidationRechecksExpiryAfterTaskLockWait(t *testing.T) {
	f := newValidationFixture(t)
	id := f.queue(t)
	f.report(t, "valid")
	if _, err := f.s.db.Exec(`UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1`, f.identity.ID); err != nil {
		t.Fatal(err)
	}
	block, err := f.s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer block.Rollback()
	if _, err = block.Exec(`SELECT id FROM uem_agent_recovery_tasks WHERE id=$1 FOR UPDATE`, id); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- f.s.checkFileVaultValidation(context.Background(), f.scope, f.d.ID, id) }()
	deadline := time.Now().Add(time.Second)
	for {
		var waiting bool
		err = f.s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE l.relation='mdm_apple_devices'::regclass AND a.wait_event_type='Lock' AND a.query LIKE 'SELECT status,result,completed_at,delivered_at FROM uem_agent_recovery_tasks%')`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("validation did not reach the held task row")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for {
		var expired bool
		if err = f.s.db.QueryRow(`SELECT certificate_expires_at<=clock_timestamp() FROM uem_agent_identities WHERE id=$1`, f.identity.ID).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err = block.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("validation remained blocked")
	}
	var status string
	var verified *time.Time
	if err = f.s.db.QueryRow(`SELECT v.status,k.verified_at FROM mdm_apple_filevault_validations v JOIN mdm_apple_filevault_keys k ON k.id=v.key_id WHERE v.id=$1`, id).Scan(&status, &verified); err != nil || status != "cancelled" || verified != nil {
		t.Fatal("pre-lock expiry check accepted an expired identity", status, err)
	}
}
