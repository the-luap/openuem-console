package apple

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func newFileVaultRotationFixture(t *testing.T) *validationFixture {
	t.Helper()
	f := newValidationFixture(t)
	f.queue(t)
	f.report(t, "valid")
	f.reconcile(t)
	testFileVaultSecurity(t, f.s, f.d, map[string]any{"FDE_Enabled": true, "FDE_HasPersonalRecoveryKey": true, "ManagementStatus": map[string]any{"UserApprovedEnrollment": true}})
	tx, err := f.s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	id, err := f.s.enqueue(t.Context(), tx, f.d, "ProfileList", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Connect(t.Context(), f.d, map[string]any{"Status": "Idle", "UDID": f.d.UDID}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Connect(t.Context(), f.d, map[string]any{"Status": "Acknowledged", "UDID": f.d.UDID, "CommandUUID": id, "ProfileList": testFileVaultProfiles(t, f.s, f.d)}); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFileVaultRotationQueueEncryptsBothDirectionsAndIsIdempotent(t *testing.T) {
	f := newFileVaultRotationFixture(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { results <- f.s.requestFileVaultRotation(t.Context(), f.scope, f.d.ID, f.keyID, "admin", nil) })
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("authorized rotation denied", err)
		}
	}
	var count int
	if err := f.s.db.QueryRow(`SELECT count(*) FROM mdm_apple_filevault_rotations WHERE device_id=$1`, f.d.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate mutation queued", count, err)
	}
	var c enrollment.RotationContext
	var bound, sealed []byte
	if err := f.s.db.QueryRow(`SELECT context,reply_private FROM mdm_apple_filevault_rotations WHERE device_id=$1`, f.d.ID).Scan(&bound, &sealed); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bound, &c); err != nil {
		t.Fatal(err)
	}
	if c.Binding.NativeID != f.d.ID || c.Binding.KeyID != f.keyID || c.Ordinal != 1 || !c.Valid(time.Now()) {
		t.Fatal("incorrect independent rotation expectation")
	}
	private, err := f.s.secrets.open(sealed, secretPurpose(f.d.TenantID, f.d.ID+"/"+c.Binding.TaskID, "filevault_rotation_reply_key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	replyKey, err := enrollment.ParseRecoveryRecipientKey(private)
	if err != nil {
		t.Fatal(err)
	}
	defer replyKey.Close()
	if hex.EncodeToString(replyKey.PublicKey()) != c.ReplyKey || bytes.Equal(replyKey.PublicKey(), f.recipient.PublicKey) {
		t.Fatal("return key reused agent material")
	}
	if _, err = f.s.secrets.open(sealed, secretPurpose(f.d.TenantID, f.d.ID+"/"+uuid.NewString(), "filevault_rotation_reply_key")); err == nil {
		t.Fatal("return key moved between tasks")
	}
	reply, err := f.access.HandleRotation(t.Context(), *f.identity, enrollment.RotationRequest{Version: 1, Protocol: enrollment.RotationProtocol, AgentID: f.identity.ID, Action: "poll", RecipientID: f.recipient.ID})
	if err != nil || reply.Task == nil || reply.Task.Context != c {
		t.Fatal("authorized task not delivered", err)
	}
	secret, err := f.private.OpenRotationTask(*reply.Task, f.recipient.Identity, f.recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	if !bytes.Equal(secret.Key(), []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) {
		t.Fatal("wrong source key encrypted")
	}
	if bytes.Contains(bound, secret.Key()) || bytes.Contains(sealed, secret.Key()) || bytes.Contains(sealed, private) {
		t.Fatal("queue stored plaintext secret")
	}
	if err = f.s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE action='apple.filevault.rotation.request'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("queue audit missing or duplicated", count, err)
	}
}

func TestFileVaultRotationQueueRequiresCurrentEvidenceAndAtomicAuthorization(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{
		{"unverified key", `UPDATE mdm_apple_filevault_keys SET verified_at=NULL`},
		{"stale validation", `UPDATE mdm_apple_filevault_keys SET verified_at=clock_timestamp()-interval '25 hours'`},
		{"stale profiles", `UPDATE mdm_apple_devices SET profiles_at=clock_timestamp()-interval '25 hours'`},
		{"missing profiles", `UPDATE mdm_apple_devices SET installed_profiles='[]'`},
		{"inactive escrow", `UPDATE mdm_apple_filevault_policies SET phase='removed',desired='removed'`},
		{"missing recipient", `DELETE FROM uem_agent_recovery_recipients`},
		{"short agent lifetime", `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()+interval '2 minutes'`},
		{"short native lifetime", `UPDATE mdm_apple_devices SET certificate_expires_at=clock_timestamp()+interval '2 minutes'`},
		{"unscoped inventory", `DELETE FROM site_agents`},
		{"audit rollback", `ALTER TABLE mdm_apple_audit ADD CONSTRAINT rotation_audit_failure CHECK(action!='apple.filevault.rotation.request')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFileVaultRotationFixture(t)
			if _, err := f.s.db.Exec(tc.sql); err != nil {
				t.Fatal(err)
			}
			if err := f.s.requestFileVaultRotation(t.Context(), f.scope, f.d.ID, f.keyID, "admin", nil); err == nil {
				t.Fatal("unsafe rotation queued")
			}
			var clean bool
			if err := f.s.db.QueryRow(`SELECT NOT EXISTS(SELECT 1 FROM mdm_apple_filevault_rotations) AND NOT EXISTS(SELECT 1 FROM uem_agent_rotation_tasks)`).Scan(&clean); err != nil || !clean {
				t.Fatal("failed queue retained mutation", err)
			}
		})
	}
	f := newFileVaultRotationFixture(t)
	if err := f.s.RequestFileVaultRotation(t.Context(), f.scope, f.d.ID, f.keyID, "admin", nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("missing permissions accepted", err)
	}
	if err := f.s.requestFileVaultRotation(t.Context(), f.scope, f.d.ID, f.keyID, "admin", func(context.Context, *sql.Tx) error { return access.ErrDenied }); !errors.Is(err, access.ErrDenied) {
		t.Fatal("denied permission accepted", err)
	}
	if err := f.s.requestFileVaultRotation(t.Context(), f.scope, f.d.ID, uuid.NewString(), "admin", nil); !errors.Is(err, ErrFileVault) {
		t.Fatal("stale key selection accepted", err)
	}
	if err := f.s.requestFileVaultRotation(t.Context(), Scope{TenantID: f.scope.TenantID + 1}, f.d.ID, f.keyID, "admin", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign scope accepted", err)
	}
}
