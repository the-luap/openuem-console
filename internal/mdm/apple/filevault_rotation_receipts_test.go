package apple

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

func queueFileVaultRotation(t *testing.T, f *validationFixture) *enrollment.RotationTask {
	t.Helper()
	if err := f.s.requestFileVaultRotation(t.Context(), f.scope, f.d.ID, f.keyID, "admin", nil); err != nil {
		t.Fatal(err)
	}
	reply, err := f.access.HandleRotation(t.Context(), *f.identity, enrollment.RotationRequest{Version: enrollment.RotationVersion, Protocol: enrollment.RotationProtocol, AgentID: f.identity.ID, Action: "poll", RecipientID: f.recipient.ID})
	if err != nil || reply.Task == nil {
		t.Fatal("rotation delivery failed", err)
	}
	return reply.Task
}

func reportFileVaultRotation(t *testing.T, f *validationFixture, task *enrollment.RotationTask, outcome string, key []byte, stopped ...bool) *enrollment.RotationResult {
	t.Helper()
	secret, err := f.private.OpenRotationTask(*task, f.recipient.Identity, f.recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	result, err := enrollment.NewRotationResult(task.Context, outcome, secret.Nonce(), key, f.cert, f.keys.Certificate, time.Now())
	if len(stopped) == 1 && stopped[0] {
		result, err = enrollment.NewStoppedRotationResult(task.Context, secret.Nonce(), f.cert, f.keys.Certificate, time.Now())
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.access.HandleRotation(t.Context(), *f.identity, enrollment.RotationRequest{Version: enrollment.RotationVersion, Protocol: enrollment.RotationProtocol, AgentID: f.identity.ID, Action: "result", Result: result}); err != nil {
		t.Fatal(err)
	}
	return result
}

func nativeFileVaultCandidate(t *testing.T, f *validationFixture, key []byte) {
	t.Helper()
	var der []byte
	if err := f.s.db.QueryRow(`SELECT certificate FROM mdm_apple_filevault_escrow WHERE device_id=$1`, f.d.ID).Scan(&der); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	testFileVaultSecurity(t, f.s, f.d, map[string]any{"FDE_Enabled": true, "FDE_HasPersonalRecoveryKey": true, "ManagementStatus": map[string]any{"UserApprovedEnrollment": true}, "FDE_PersonalRecoveryKeyDeviceKey": f.d.ID, "FDE_PersonalRecoveryKeyCMS": testFileVaultEnvelope(t, cert, key, fileVaultAES256OID, false)})
}

func rotationState(t *testing.T, f *validationFixture, id, status string) {
	t.Helper()
	var actual string
	if err := f.s.db.QueryRow(`SELECT status FROM mdm_apple_filevault_rotations WHERE id=$1`, id).Scan(&actual); err != nil || actual != status {
		t.Fatal("unexpected rotation state", actual, status, err)
	}
}

func TestFileVaultRotationReceiptsRetainKeysAndRespectNativeEscrowOrdering(t *testing.T) {
	newKey := []byte("1111-2222-3333-4444-5555-6666")
	for _, mode := range []string{"rotated", "unverified", "native_first", "newer_unrelated", "audit_rollback"} {
		t.Run(mode, func(t *testing.T) {
			f := newFileVaultRotationFixture(t)
			task := queueFileVaultRotation(t, f)
			if mode == "native_first" {
				nativeFileVaultCandidate(t, f, newKey)
			}
			outcome := "rotated"
			if mode == "unverified" {
				outcome = mode
			}
			reportFileVaultRotation(t, f, task, outcome, newKey)
			if mode == "newer_unrelated" {
				nativeFileVaultCandidate(t, f, []byte("2222-3333-4444-5555-6666-7777"))
			}
			if mode == "audit_rollback" {
				if _, err := f.s.db.Exec(`ALTER TABLE mdm_apple_audit ADD CONSTRAINT rotation_receipt_audit_failure CHECK(action!='apple.filevault.rotation.rotated')`); err != nil {
					t.Fatal(err)
				}
				if err := f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, task.Context.Binding.TaskID); err == nil {
					t.Fatal("receipt ignored audit failure")
				}
				var rolledBack bool
				if err := f.s.db.QueryRow(`SELECT status='queued' AND octet_length(reply_private)>0 AND (SELECT count(*) FROM mdm_apple_filevault_keys)=1 FROM mdm_apple_filevault_rotations WHERE id=$1`, task.Context.Binding.TaskID).Scan(&rolledBack); err != nil || !rolledBack {
					t.Fatal("receipt transaction partly committed", err)
				}
				if _, err := f.s.db.Exec(`ALTER TABLE mdm_apple_audit DROP CONSTRAINT rotation_receipt_audit_failure`); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				if err := f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, task.Context.Binding.TaskID); err != nil {
					t.Fatal(err)
				}
			}
			expect := outcome
			if mode == "newer_unrelated" {
				expect = "superseded"
			}
			rotationState(t, f, task.Context.Binding.TaskID, expect)
			var candidate, current string
			var erased, verified bool
			if err := f.s.db.QueryRow(`SELECT r.candidate_key_id,p.current_key_id,octet_length(r.reply_private)=0,k.verified_at IS NOT NULL FROM mdm_apple_filevault_rotations r JOIN mdm_apple_filevault_policies p ON p.device_id=r.device_id JOIN mdm_apple_filevault_keys k ON k.id=r.candidate_key_id WHERE r.id=$1`, task.Context.Binding.TaskID).Scan(&candidate, &current, &erased, &verified); err != nil || !erased || verified != (outcome == "rotated") {
				t.Fatal("candidate state or secret erasure incorrect", err)
			}
			if mode == "newer_unrelated" && candidate == current || mode != "newer_unrelated" && candidate != current {
				t.Fatal("rotation replaced wrong current key")
			}
			plain, err := f.s.revealFileVaultKey(t.Context(), f.scope, f.d.ID, candidate, "admin", nil)
			if err != nil || !bytes.Equal(plain, newKey) {
				t.Fatal("candidate unavailable through escrow", err)
			}
			clear(plain)
			plain, err = f.s.revealFileVaultKey(t.Context(), f.scope, f.d.ID, f.keyID, "admin", nil)
			if err != nil || !bytes.Equal(plain, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) {
				t.Fatal("old key lost", err)
			}
			clear(plain)
			history, err := f.s.FileVaultKeyHistory(t.Context(), f.scope, f.d.ID)
			if err != nil {
				t.Fatal(err)
			}
			count := 2
			if mode == "newer_unrelated" {
				count = 3
			}
			if len(history) != count {
				t.Fatal("candidate duplicated or history lost", len(history))
			}
			if mode == "newer_unrelated" {
				nativeFileVaultCandidate(t, f, newKey)
				var reused bool
				if err = f.s.db.QueryRow(`SELECT current_key_id=$2 AND (SELECT count(*) FROM mdm_apple_filevault_keys)=3 FROM mdm_apple_filevault_policies WHERE device_id=$1`, f.d.ID, candidate).Scan(&reused); err != nil || !reused {
					t.Fatal("later native escrow duplicated the retained candidate", err)
				}
			}
			if mode == "unverified" {
				if err = f.s.requestFileVaultRotation(t.Context(), f.scope, f.d.ID, current, "admin", nil); err == nil {
					t.Fatal("unverified candidate admitted another mutation")
				}
			}
		})
	}
}

func TestFileVaultRotationUncertaintyNeedsIndependentCurrentKeyProof(t *testing.T) {
	f := newFileVaultRotationFixture(t)
	task := queueFileVaultRotation(t, f)
	reportFileVaultRotation(t, f, task, "uncertain", nil, true)
	if err := f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, task.Context.Binding.TaskID); err != nil {
		t.Fatal(err)
	}
	rotationState(t, f, task.Context.Binding.TaskID, "uncertain")
	if err := f.s.requestFileVaultRotation(t.Context(), f.scope, f.d.ID, f.keyID, "admin", nil); err == nil {
		t.Fatal("uncertainty retried mutation")
	}
	if err := f.s.setFileVault(t.Context(), f.scope, f.d.ID, "removed", "admin", nil); err == nil {
		t.Fatal("uncertainty removed escrow profiles")
	}
	f.queue(t)
	f.report(t, "invalid")
	f.reconcile(t)
	rotationState(t, f, task.Context.Binding.TaskID, "uncertain")
	f.queue(t)
	f.report(t, "valid")
	f.reconcile(t)
	rotationState(t, f, task.Context.Binding.TaskID, "resolved")
	var retained bool
	if err := f.s.db.QueryRow(`SELECT t.status='completed' AND t.resolved_at IS NOT NULL AND octet_length(t.result)>0 AND octet_length(r.reply_private)=0 FROM uem_agent_rotation_tasks t JOIN mdm_apple_filevault_rotations r ON r.id=t.id WHERE t.id=$1`, task.Context.Binding.TaskID).Scan(&retained); err != nil || !retained {
		t.Fatal("resolution lost receipt/proof", err)
	}
	if next := queueFileVaultRotation(t, f); next.Context.Ordinal != 2 {
		t.Fatal("resolution reused attempt")
	}
}

func TestFileVaultRotationValidationRequiresAuthenticStoppingEvidence(t *testing.T) {
	for _, mode := range []string{"legacy", "forged-flag", "forged-signature", "stopped"} {
		t.Run(mode, func(t *testing.T) {
			f := newFileVaultRotationFixture(t)
			task := queueFileVaultRotation(t, f)
			result := reportFileVaultRotation(t, f, task, "uncertain", nil, mode == "stopped" || mode == "forged-signature")
			if err := f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, task.Context.Binding.TaskID); err != nil {
				t.Fatal(err)
			}
			if mode == "forged-flag" || mode == "forged-signature" {
				if mode == "forged-flag" {
					result.ExecutionStopped = true
				} else {
					result.Signature[0] ^= 1
				}
				wire, _ := json.Marshal(result)
				if _, err := f.s.db.Exec(`UPDATE uem_agent_rotation_tasks SET result=$2 WHERE id=$1`, task.Context.Binding.TaskID, wire); err != nil {
					t.Fatal(err)
				}
			}
			v, err := f.s.FileVault(t.Context(), f.scope, f.d.ID)
			ready := mode == "stopped"
			if err != nil || v.Rotation == nil || v.Rotation.ExecutionStopped != ready || v.ValidationReady != ready || v.RotationReady {
				t.Fatal("unsafe stopping metadata", err)
			}
			err = f.s.requestFileVaultValidation(t.Context(), f.scope, f.d.ID, f.keyID, "admin", nil)
			if (err == nil) != ready {
				t.Fatal("old-key resolution ignored stopping evidence", err)
			}
			if err := f.s.requestFileVaultRotation(t.Context(), f.scope, f.d.ID, f.keyID, "admin", nil); err == nil {
				t.Fatal("stopping receipt alone unblocked mutation")
			}
		})
	}
}

func TestFileVaultRotationReceiptRejectsIndependentContextAndSignatureChanges(t *testing.T) {
	for _, mode := range []string{"nonce", "signature", "native_context", "same_key"} {
		t.Run(mode, func(t *testing.T) {
			f := newFileVaultRotationFixture(t)
			task := queueFileVaultRotation(t, f)
			key := []byte("1111-2222-3333-4444-5555-6666")
			if mode == "same_key" {
				key = []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")
			}
			result := reportFileVaultRotation(t, f, task, "rotated", key)
			switch mode {
			case "nonce":
				result.Nonce[0] ^= 1
			case "signature":
				result.Signature[0] ^= 1
			case "native_context":
				if _, err := f.s.db.Exec(`UPDATE mdm_apple_filevault_rotations SET nonce_hash=repeat('0',64) WHERE id=$1`, task.Context.Binding.TaskID); err != nil {
					t.Fatal(err)
				}
			}
			wire, _ := json.Marshal(result)
			if _, err := f.s.db.Exec(`UPDATE uem_agent_rotation_tasks SET result=$2 WHERE id=$1`, task.Context.Binding.TaskID, wire); err != nil {
				t.Fatal(err)
			}
			if err := f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, task.Context.Binding.TaskID); err != nil {
				t.Fatal(err)
			}
			rotationState(t, f, task.Context.Binding.TaskID, "rejected")
			var unchanged bool
			if err := f.s.db.QueryRow(`SELECT current_key_id=$2 AND (SELECT count(*) FROM mdm_apple_filevault_keys)=1 FROM mdm_apple_filevault_policies WHERE device_id=$1`, f.d.ID, f.keyID).Scan(&unchanged); err != nil || !unchanged {
				t.Fatal("rejected receipt changed key", err)
			}
		})
	}
}

func TestFileVaultRotationDeliveryStopsWhenNativeAuthorityChanges(t *testing.T) {
	for _, change := range []string{
		`UPDATE uem_mac_agent_channels SET retired_at=clock_timestamp()`,
		`UPDATE uem_mac_mdm_channels SET retired_at=clock_timestamp()`,
		`UPDATE uem_agent_hardware SET serial='CHANGED123'`,
		`UPDATE uem_mac_devices SET serial='CHANGED123'`,
		`UPDATE mdm_apple_devices SET status='revoked'`,
		`UPDATE mdm_apple_filevault_policies SET phase='failed'`,
		`DELETE FROM uem_agent_hardware`,
		`DELETE FROM uem_mac_agent_channels`,
		`DELETE FROM uem_mac_mdm_channels`,
	} {
		t.Run(change, func(t *testing.T) {
			f := newFileVaultRotationFixture(t)
			if err := f.s.requestFileVaultRotation(t.Context(), f.scope, f.d.ID, f.keyID, "admin", nil); err != nil {
				t.Fatal(err)
			}
			if _, err := f.s.db.Exec(change); err != nil {
				t.Fatal(err)
			}
			var cancelled bool
			if err := f.s.db.QueryRow(`SELECT status='cancelled' AND octet_length(envelope)=0 AND delivered_at IS NULL FROM uem_agent_rotation_tasks WHERE device_id=$1`, f.identity.ID).Scan(&cancelled); err != nil || !cancelled {
				t.Fatal("authority change left mutation deliverable", err)
			}
			reply, err := f.access.HandleRotation(t.Context(), *f.identity, enrollment.RotationRequest{Version: enrollment.RotationVersion, Protocol: enrollment.RotationProtocol, AgentID: f.identity.ID, Action: "poll", RecipientID: f.recipient.ID})
			if err != nil || reply.Task != nil || reply.Receipt != nil {
				t.Fatal("invalidated mutation delivered", err)
			}
		})
	}
}

func TestFileVaultRotationLateReceiptAndHistoricalCapacityPreserveCandidate(t *testing.T) {
	for _, mode := range []string{"late", "history_full"} {
		t.Run(mode, func(t *testing.T) {
			f := newFileVaultRotationFixture(t)
			task := queueFileVaultRotation(t, f)
			secret, err := f.private.OpenRotationTask(*task, f.recipient.Identity, f.recipient.ID, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Close()
			c := task.Context
			if mode == "late" {
				c.Binding.ExpiresAt = time.Now().Add(-time.Second).Unix()
				bound, _ := json.Marshal(c)
				if _, err = f.s.db.Exec(`UPDATE uem_agent_rotation_tasks SET context=$2,expires_at=to_timestamp($3),created_at=to_timestamp($3)-interval '10 seconds',delivered_at=to_timestamp($3)-interval '5 seconds' WHERE id=$1`, c.Binding.TaskID, bound, c.Binding.ExpiresAt); err != nil {
					t.Fatal(err)
				}
				if _, err = f.s.db.Exec(`UPDATE mdm_apple_filevault_rotations SET context=$2,expires_at=to_timestamp($3),created_at=to_timestamp($3)-interval '9 seconds' WHERE id=$1`, c.Binding.TaskID, bound, c.Binding.ExpiresAt); err != nil {
					t.Fatal(err)
				}
			}
			result, err := enrollment.NewRotationResult(c, "rotated", secret.Nonce(), []byte("1111-2222-3333-4444-5555-6666"), f.cert, f.keys.Certificate, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.access.HandleRotation(t.Context(), *f.identity, enrollment.RotationRequest{Version: enrollment.RotationVersion, Protocol: enrollment.RotationProtocol, AgentID: f.identity.ID, Action: "result", Result: result}); err != nil {
				t.Fatal("late receipt rejected", err)
			}
			var removable string
			if mode == "history_full" {
				tx, err := f.s.db.BeginTx(t.Context(), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				for range 127 {
					removable = uuid.NewString()
					sealed, err := f.s.secrets.seal([]byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), secretPurpose(f.d.TenantID, f.d.ID+"/"+removable, "filevault_recovery_key"))
					if err != nil {
						t.Fatal(err)
					}
					if _, err = tx.Exec(`INSERT INTO mdm_apple_filevault_keys(id,tenant_id,device_id,escrow_id,recovery_key) VALUES($1,$2,$3,$4,$5)`, removable, f.d.TenantID, f.d.ID, c.EscrowID, sealed); err != nil {
						t.Fatal(err)
					}
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
				if err = f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, c.Binding.TaskID); err != nil {
					t.Fatal(err)
				}
				var preserved bool
				if err = f.s.db.QueryRow(`SELECT r.status='queued' AND octet_length(r.reply_private)>0 AND octet_length(t.result)>0 AND p.recovery_error='recovery_history_full' FROM mdm_apple_filevault_rotations r JOIN uem_agent_rotation_tasks t ON t.id=r.id JOIN mdm_apple_filevault_policies p ON p.device_id=r.device_id WHERE r.id=$1`, c.Binding.TaskID).Scan(&preserved); err != nil || !preserved {
					t.Fatal("capacity discarded candidate", err)
				}
				// Only the disposable fixture frees a synthetic history slot. There
				// is no production history-deletion or automatic forget operation.
				if _, err = f.s.db.Exec(`DELETE FROM mdm_apple_filevault_keys WHERE id=$1`, removable); err != nil {
					t.Fatal(err)
				}
			}
			if err = f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, c.Binding.TaskID); err != nil {
				t.Fatal(err)
			}
			rotationState(t, f, c.Binding.TaskID, "rotated")
		})
	}
}

func TestFileVaultRotationRefusesKeyDisprovenAfterHistoricalSuccess(t *testing.T) {
	f := newFileVaultRotationFixture(t)
	f.queue(t)
	f.report(t, "invalid")
	f.reconcile(t)
	if err := f.s.requestFileVaultRotation(t.Context(), f.scope, f.d.ID, f.keyID, "admin", nil); err == nil {
		t.Fatal("historical success overruled newer invalid result")
	}
	v, err := f.s.FileVault(t.Context(), f.scope, f.d.ID)
	if err != nil || v.VerifiedAt == nil || v.RotationReady {
		t.Fatal("history erased or invalid key advertised for rotation", err)
	}
	f.queue(t)
	f.report(t, "valid")
	f.reconcile(t)
	queueFileVaultRotation(t, f)
}
