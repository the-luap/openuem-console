package apple

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

const historicalTestKey = "1111-2222-3333-4444-5555-6666"

func eraseSyntheticHistoricalAcknowledgement(t *testing.T, f *validationFixture, id string) {
	t.Helper()
	// Only the disposable test schema recreates a pre-acknowledgement console.
	if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_rotation_reconciliations DISABLE TRIGGER uem_agent_rotation_reconciliation_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec(`DELETE FROM uem_agent_rotation_reconciliations WHERE task_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec(`ALTER TABLE uem_agent_rotation_reconciliations ENABLE TRIGGER uem_agent_rotation_reconciliation_immutable`); err != nil {
		t.Fatal(err)
	}
}

func historicalFileVaultFixture(t *testing.T, outcome string) (*validationFixture, *enrollment.RotationTask) {
	t.Helper()
	f := newFileVaultRotationFixture(t)
	shortenRotationFixtureIdentity(t, f)
	task := queueFileVaultRotation(t, f)
	var key []byte
	if outcome == "rotated" || outcome == "unverified" {
		key = []byte(historicalTestKey)
	}
	reportFileVaultRotation(t, f, task, outcome, key)
	if err := f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, task.Context.Binding.TaskID); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow(`SELECT current_key_id FROM mdm_apple_filevault_policies WHERE device_id=$1`, f.d.ID).Scan(&f.keyID); err != nil {
		t.Fatal(err)
	}
	eraseSyntheticHistoricalAcknowledgement(t, f, task.Context.Binding.TaskID)
	return f, task
}

func historicalRenewalConfirmation(t *testing.T, f *validationFixture) *enrollment.RenewalConfirmation {
	t.Helper()
	candidate, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(candidate.Broker.Wipe)
	broker, _ := f.keys.Broker.PublicKey()
	source := enrollment.RenewalSource{DeviceID: f.identity.ID, TenantID: 1, SiteID: 1, Origin: "https://uem.example.test", Platform: "macos", Architecture: "arm64", BrokerKey: broker, Certificate: f.cert.Raw}
	request, err := enrollment.NewRenewalRequest(source, f.keys, candidate, uuid.NewString(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.registry.PrepareIdentityRenewal(t.Context(), *request)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := enrollment.ValidateResponse(prepared.Response, source.Origin, &candidate.Certificate.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	target := enrollment.RenewalConfirmationTarget{RequestID: prepared.ID, SourceCertificateHash: prepared.SourceCertificateHash, Candidate: source}
	target.Candidate.Certificate = issued.Raw
	target.Candidate.BrokerKey, _ = candidate.Broker.PublicKey()
	confirm, err := enrollment.NewRenewalConfirmation(target, candidate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return confirm
}

func reportHistoricalFileVaultValidation(t *testing.T, f *validationFixture, outcome string) string {
	t.Helper()
	reply, err := f.access.HandleRecovery(t.Context(), *f.identity, enrollment.RecoveryRequest{Version: 1, AgentID: f.identity.ID, Action: "poll", RecipientID: f.recipient.ID})
	if err != nil || reply.Task == nil {
		t.Fatal("historical challenge not delivered", err)
	}
	secret, err := f.private.Open(*reply.Task, f.recipient.Identity, f.recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	if !bytes.Equal(secret.Key(), []byte(historicalTestKey)) {
		t.Fatal("historical challenge did not carry the current retained key")
	}
	result, err := secret.Result(outcome, f.cert, f.keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.access.HandleRecovery(t.Context(), *f.identity, enrollment.RecoveryRequest{Version: 1, AgentID: f.identity.ID, Action: "result", Result: result}); err != nil {
		t.Fatal(err)
	}
	return reply.Task.Context.TaskID
}

func TestFileVaultHistoricalRecoveryReleasesRenewalAfterErasedReturnKey(t *testing.T) {
	f, rotation := historicalFileVaultFixture(t, "rotated")
	confirm := historicalRenewalConfirmation(t, f)
	if _, err := f.registry.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, registry.ErrRenewalRecoveryPending) {
		t.Fatal("unreconciled history allowed renewal", err)
	}
	var oldWire []byte
	var erased bool
	if err := f.s.db.QueryRow(`SELECT t.result,octet_length(v.reply_private)=0 FROM mdm_apple_filevault_rotations v JOIN uem_agent_rotation_tasks t ON t.id=v.id WHERE v.id=$1`, rotation.Context.Binding.TaskID).Scan(&oldWire, &erased); err != nil || !erased {
		t.Fatal("fixture did not erase old return key", err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 4)
	for range 4 {
		wg.Go(func() { failures <- f.s.ReconcileFileVaultHistory(t.Context()) })
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := f.s.db.QueryRow(`SELECT count(*) FROM uem_agent_rotation_recovery_checks`).Scan(&count); err != nil || count != 1 {
		t.Fatal("replicas duplicated historical challenge", count, err)
	}
	v, err := f.s.FileVault(t.Context(), f.scope, f.d.ID)
	if err != nil || v.HistoricalRotationsPending != 1 || v.HistoricalRotationsNeedAttention {
		t.Fatal("missing public historical state", err)
	}
	id := reportHistoricalFileVaultValidation(t, f, "valid")
	if _, err = f.registry.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, registry.ErrRenewalRecoveryPending) {
		t.Fatal("routing worker bypassed trusted processing", err)
	}
	if err = f.s.checkFileVaultValidation(t.Context(), f.scope, f.d.ID, id); err != nil {
		t.Fatal(err)
	}
	historicalAcknowledgementState(t, f, rotation.Context.Binding.TaskID, true)
	if _, err = f.registry.ConfirmIdentityRenewal(t.Context(), *confirm); err != nil {
		t.Fatal("historical current-key proof did not release renewal", err)
	}
	var intact bool
	if err = f.s.db.QueryRow(`SELECT t.result=$2 AND v.status='rotated' AND octet_length(v.reply_private)=0 AND (SELECT count(*) FROM mdm_apple_filevault_keys)=2 FROM mdm_apple_filevault_rotations v JOIN uem_agent_rotation_tasks t ON t.id=v.id WHERE v.id=$1`, rotation.Context.Binding.TaskID, oldWire).Scan(&intact); err != nil || !intact {
		t.Fatal("historical reconciliation rewrote evidence or key history", err)
	}
	v, err = f.s.FileVault(t.Context(), f.scope, f.d.ID)
	if err != nil || v.HistoricalRotationsPending != 0 {
		t.Fatal("released history remained pending", err)
	}
}

func TestFileVaultHistoricalAuditFailureRollsBackAllReleaseState(t *testing.T) {
	f, rotation := historicalFileVaultFixture(t, "rotated")
	f.queue(t)
	id := reportHistoricalFileVaultValidation(t, f, "valid")
	var verified time.Time
	if err := f.s.db.QueryRow(`SELECT verified_at FROM mdm_apple_filevault_keys WHERE id=$1`, f.keyID).Scan(&verified); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec(`CREATE FUNCTION reject_history_validation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.filevault.validation.valid' THEN RAISE EXCEPTION 'synthetic validation audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_history_validation_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_history_validation_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := f.s.checkFileVaultValidation(t.Context(), f.scope, f.d.ID, id); err == nil {
		t.Fatal("failed console audit committed reconciliation")
	}
	historicalAcknowledgementState(t, f, rotation.Context.Binding.TaskID, false)
	var intact bool
	if err := f.s.db.QueryRow(`SELECT v.status='queued' AND k.verified_at=$3 FROM mdm_apple_filevault_validations v JOIN mdm_apple_filevault_keys k ON k.id=$2 WHERE v.id=$1`, id, f.keyID, verified).Scan(&intact); err != nil || !intact {
		t.Fatal("audit failure partly updated validation", err)
	}
	if _, err := f.s.db.Exec(`DROP TRIGGER reject_history_validation_audit ON mdm_apple_audit`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := f.s.checkFileVaultValidation(t.Context(), f.scope, f.d.ID, id); err != nil {
			t.Fatal("retry failed", err)
		}
	}
	historicalAcknowledgementState(t, f, rotation.Context.Binding.TaskID, true)
}

func TestFileVaultHistoricalFailedOrChangedKeyNeverAcknowledges(t *testing.T) {
	for _, mode := range []string{"invalid", "unsupported", "unavailable", "changed ciphertext"} {
		t.Run(mode, func(t *testing.T) {
			f, rotation := historicalFileVaultFixture(t, "rotated")
			f.queue(t)
			outcome := mode
			if mode == "changed ciphertext" {
				outcome = "valid"
			}
			id := reportHistoricalFileVaultValidation(t, f, outcome)
			if mode == "changed ciphertext" {
				sealed, err := f.s.secrets.seal([]byte(historicalTestKey), secretPurpose(f.d.TenantID, f.d.ID+"/"+f.keyID, "filevault_recovery_key"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.s.db.Exec(`UPDATE mdm_apple_filevault_keys SET recovery_key=$2 WHERE id=$1`, f.keyID, sealed); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.s.checkFileVaultValidation(t.Context(), f.scope, f.d.ID, id); err != nil {
				t.Fatal(err)
			}
			historicalAcknowledgementState(t, f, rotation.Context.Binding.TaskID, false)
			var deferred bool
			if err := f.s.db.QueryRow(`SELECT history_status='attention' AND history_next_check_at>clock_timestamp()+interval '23 hours' FROM mdm_apple_filevault_rotations WHERE id=$1`, rotation.Context.Binding.TaskID).Scan(&deferred); err != nil || !deferred {
				t.Fatal("failed historical proof did not back off", err)
			}
			if err := f.s.ReconcileFileVaultHistory(t.Context()); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := f.s.db.QueryRow(`SELECT count(*) FROM uem_agent_rotation_recovery_checks`).Scan(&count); err != nil || count != 1 {
				t.Fatal("failed proof immediately retried", err)
			}
		})
	}
}

func TestFileVaultHistoricalNonMutatingReceiptNeedsNoCurrentKey(t *testing.T) {
	f, rotation := historicalFileVaultFixture(t, "unsupported")
	if _, err := f.s.db.Exec(`UPDATE mdm_apple_filevault_policies SET current_key_id=NULL WHERE device_id=$1`, f.d.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.s.ReconcileFileVaultHistory(t.Context()); err != nil {
		t.Fatal(err)
	}
	historicalAcknowledgementState(t, f, rotation.Context.Binding.TaskID, true)
	var count int
	if err := f.s.db.QueryRow(`SELECT count(*) FROM uem_agent_rotation_recovery_checks`).Scan(&count); err != nil || count != 0 {
		t.Fatal("non-mutating receipt requested a key challenge", err)
	}
}

func TestFileVaultHistoricalMaintenancePreservesOrdinaryPendingValidation(t *testing.T) {
	f := newFileVaultRotationFixture(t)
	rotation := queueFileVaultRotation(t, f)
	reportFileVaultRotation(t, f, rotation, "rotated", []byte(historicalTestKey))
	if err := f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, rotation.Context.Binding.TaskID); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow(`SELECT current_key_id FROM mdm_apple_filevault_policies WHERE device_id=$1`, f.d.ID).Scan(&f.keyID); err != nil {
		t.Fatal(err)
	}
	ordinary := f.queue(t)
	eraseSyntheticHistoricalAcknowledgement(t, f, rotation.Context.Binding.TaskID)
	if err := f.s.ReconcileFileVaultHistory(t.Context()); err != nil {
		t.Fatal(err)
	}
	var untouched bool
	if err := f.s.db.QueryRow(`SELECT status='pending' AND NOT EXISTS(SELECT 1 FROM uem_agent_rotation_recovery_checks) FROM uem_agent_recovery_tasks WHERE id=$1`, ordinary).Scan(&untouched); err != nil || !untouched {
		t.Fatal("history cancelled ordinary validation", err)
	}
	reportHistoricalFileVaultValidation(t, f, "valid")
	if err := f.s.checkFileVaultValidation(t.Context(), f.scope, f.d.ID, ordinary); err != nil {
		t.Fatal(err)
	}
	historicalAcknowledgementState(t, f, rotation.Context.Binding.TaskID, false)
	bound := f.queue(t)
	if bound == ordinary {
		t.Fatal("ordinary validation reused as bound history proof")
	}
	id := reportHistoricalFileVaultValidation(t, f, "valid")
	if err := f.s.checkFileVaultValidation(t.Context(), f.scope, f.d.ID, id); err != nil {
		t.Fatal(err)
	}
	historicalAcknowledgementState(t, f, rotation.Context.Binding.TaskID, true)
}

func historicalAcknowledgementState(t *testing.T, f *validationFixture, id string, present bool) {
	t.Helper()
	expected := 0
	if present {
		expected = 1
	}
	var rows, audits int
	if err := f.s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_rotation_reconciliations WHERE task_id=$1),(SELECT count(*) FROM uem_agent_audit WHERE resource_id=$1 AND action='recovery.rotation.historically-reconciled')`, id).Scan(&rows, &audits); err != nil || rows != expected || audits != expected {
		t.Fatal("incorrect historical acknowledgement or audit", rows, audits, err)
	}
}

func TestFileVaultHistoricalReleaseRechecksExpiryAfterConsoleAudit(t *testing.T) {
	f, rotation := historicalFileVaultFixture(t, "rotated")
	f.queue(t)
	id := reportHistoricalFileVaultValidation(t, f, "valid")
	// Only a disposable fixture shortens its own metadata during the final
	// audit; the signed certificate and real application clocks remain intact.
	if _, err := f.s.db.Exec(`CREATE FUNCTION expire_history_identity_on_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.filevault.validation.valid' THEN UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second'; END IF; RETURN NEW; END $$; CREATE TRIGGER expire_history_identity_on_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION expire_history_identity_on_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := f.s.checkFileVaultValidation(t.Context(), f.scope, f.d.ID, id); !errors.Is(err, ErrFileVault) {
		t.Fatal("certificate expiry during audit released history", err)
	}
	historicalAcknowledgementState(t, f, rotation.Context.Binding.TaskID, false)
	var pending bool
	if err := f.s.db.QueryRow(`SELECT status='queued' FROM mdm_apple_filevault_validations WHERE id=$1`, id).Scan(&pending); err != nil || !pending {
		t.Fatal("expired authority partly committed completion", err)
	}
}

func TestFileVaultHistoricalAdmissionAndNonKeyReleaseRecheckExpiryAfterAudit(t *testing.T) {
	for _, mode := range []string{"admission", "non-key"} {
		t.Run(mode, func(t *testing.T) {
			outcome, action := "rotated", "apple.filevault.validation.request"
			if mode == "non-key" {
				outcome, action = "unsupported", "apple.filevault.rotation.history.non-mutating"
			}
			f, rotation := historicalFileVaultFixture(t, outcome)
			if _, err := f.s.db.Exec(`CREATE FUNCTION expire_history_authority_on_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action=TG_ARGV[0] THEN UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second'; END IF; RETURN NEW; END $$`); err != nil {
				t.Fatal(err)
			}
			// Both action names above are fixed test constants, never user input.
			if _, err := f.s.db.Exec(`CREATE TRIGGER expire_history_authority_on_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION expire_history_authority_on_audit('` + action + `')`); err != nil {
				t.Fatal(err)
			}
			if err := f.s.checkFileVaultHistory(t.Context(), f.scope, f.d.ID, rotation.Context.Binding.TaskID); !errors.Is(err, ErrFileVault) {
				t.Fatal("expired authority admitted historical work", err)
			}
			historicalAcknowledgementState(t, f, rotation.Context.Binding.TaskID, false)
			var count int
			if err := f.s.db.QueryRow(`SELECT count(*) FROM uem_agent_rotation_recovery_checks`).Scan(&count); err != nil || count != 0 {
				t.Fatal("expired authority committed admission", err)
			}
		})
	}
}

func TestFileVaultHistoricalResolvedUncertaintyPreservesOriginalResolution(t *testing.T) {
	f := newFileVaultRotationFixture(t)
	rotation := queueFileVaultRotation(t, f)
	reportFileVaultRotation(t, f, rotation, "uncertain", nil, true)
	if err := f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, rotation.Context.Binding.TaskID); err != nil {
		t.Fatal(err)
	}
	resolution := f.queue(t)
	f.report(t, "valid")
	f.reconcile(t)
	eraseSyntheticHistoricalAcknowledgement(t, f, rotation.Context.Binding.TaskID)
	if _, err := f.s.db.Exec(`UPDATE uem_agent_rotation_tasks SET resolved_at=clock_timestamp() WHERE id=$1`, rotation.Context.Binding.TaskID); err != nil {
		t.Fatal(err)
	}
	history := f.queue(t)
	if history == resolution {
		t.Fatal("old resolution proof reused as historical challenge")
	}
	f.report(t, "valid")
	f.reconcile(t)
	historicalAcknowledgementState(t, f, rotation.Context.Binding.TaskID, true)
	var retained bool
	if err := f.s.db.QueryRow(`SELECT t.resolution_task_id=$2 AND v.status='resolved' AND octet_length(v.reply_private)=0 AND (SELECT count(*) FROM mdm_apple_filevault_keys)=1 FROM uem_agent_rotation_tasks t JOIN mdm_apple_filevault_rotations v ON v.id=t.id WHERE t.id=$1`, rotation.Context.Binding.TaskID, resolution).Scan(&retained); err != nil || !retained {
		t.Fatal("historical processing rewrote uncertainty resolution", err)
	}
}
