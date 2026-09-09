package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestUpdateCreatorRevisionGuardsDeliveryButPreservesDeviceEvidence(t *testing.T) {
	for _, sent := range []bool{false, true} {
		f := syncMLTestStore(t)
		policy := updateTestPolicy()
		run := updateTestQueue(t, f, policy, false)
		var request, response []byte
		if sent {
			request, response = cspTestStart(t, f)
		}
		principal, err := f.store.permissions.Principal(context.Background(), "operator")
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.permissions.ReplaceGrants(context.Background(), "admin", "operator", principal.Revision, []access.Grant{{Role: access.Operator, Scope: f.identity.Scope}}); err != nil {
			t.Fatal(err)
		}
		if sent {
			if data, err := f.process(request); !errors.Is(err, access.ErrDenied) || data != nil {
				t.Fatal("stale update authority replayed delivery", err)
			}
			if _, err := f.process(syncMLTestWire(t, updateTestReply(syncMLTestParsed(t, response), policy, false, false))); err != nil {
				t.Fatal("authority change discarded authenticated evidence", err)
			}
		} else {
			cspTestStart(t, f)
		}
		detail := updateTestRead(t, f, run.ID)
		if detail.Steps[1].Phase != "canceled" || detail.Steps[2].Phase != "canceled" {
			t.Fatal("changed creator authority permitted later mutation")
		}
		if sent && detail.Steps[0].Phase != "acknowledged" {
			t.Fatal("completed platform evidence was lost")
		}
	}
}

func TestUpdateCapabilityCannotAuthorizeSubstitutedRawCSP(t *testing.T) {
	f := syncMLTestStore(t)
	run := updateTestQueue(t, f, updateTestPolicy(), false)
	c, err := scanCSPCommand(f.store.db.QueryRow(`SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE update_run_id=$1 AND update_step=0`, run.ID))
	if err != nil {
		t.Fatal(err)
	}
	changed := *c
	changed.UpdateRunID = ""
	if data, _, err := f.store.openCSPRequest(&changed); err == nil || data != nil {
		t.Fatal("typed ciphertext became custom authority")
	}
	changed = *c
	changed.UpdateStep = 1
	if data, _, err := f.store.openCSPRequest(&changed); err == nil || data != nil {
		t.Fatal("typed ciphertext moved to a different step")
	}
	if _, err := f.store.db.Exec(`UPDATE mdm_windows_csp_commands SET revision=revision+1,update_run_id=NULL,update_step=NULL WHERE id=$1`, c.ID); err == nil {
		t.Fatal("SQL allowed update authority reassignment")
	}
	// Only this owned test schema simulates correctly encrypted but substituted
	// storage. The payload remains in memory and is never executed by the host.
	payload, _, err := encodeCSPRequest(CSPCommandSpec{Kind: "Exec", URI: "./Device/Vendor/MSFT/Synthetic/Execute"})
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{3}, 32)
	c.digest = cspRequestDigest(salt, payload)
	plain, err := json.Marshal(cspProtectedRequest{Version: 1, Salt: salt, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	c.request, err = f.store.secrets.sealBounded(plain, cspPurpose("request", c), maxCSPProtectedBytes)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE mdm_windows_csp_commands DISABLE TRIGGER mdm_windows_csp_command_identity`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE mdm_windows_csp_commands SET request_digest=$2,encrypted_request=$3 WHERE id=$1`, c.ID, c.digest, c.request); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`ALTER TABLE mdm_windows_csp_commands ENABLE TRIGGER mdm_windows_csp_command_identity`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	first, err := f.process(f.initial(t))
	if err != nil {
		t.Fatal(err)
	}
	if data, err := f.process(syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))); !errors.Is(err, ErrAuthoritySecret) || data != nil {
		t.Fatal("update authority released an arbitrary custom operation", err)
	}
	if detail, err := f.store.UpdateRunDetails(context.Background(), "operator", f.identity.Scope, f.identity.DeviceID, run.ID); !errors.Is(err, ErrAuthoritySecret) || detail != nil {
		t.Fatal("substituted update intent appeared legitimate", err)
	}
}

func TestUpdateMigrationPreservesExistingCustomDelivery(t *testing.T) {
	f := syncMLTestStore(t)
	queued := cspTestQueue(t, f, cspTestPolicy())
	request, response := cspTestStart(t, f)
	updateTestRemoveRingMigration(t, f.store)
	if _, err := f.store.db.Exec(`ALTER TABLE mdm_windows_csp_commands DROP COLUMN update_run_id,DROP COLUMN update_step; DROP TABLE mdm_windows_update_audit,mdm_windows_update_runs; DELETE FROM mdm_windows_migrations WHERE name IN ('migrations/006_update_runs.sql','migrations/007_update_verification_batches.sql')`); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		if err := f.store.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if replay, err := f.process(request); err != nil || !bytes.Equal(replay, response) {
		t.Fatal("update migration changed existing CSP ciphertext authority", err)
	}
	if _, err := f.process(syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, response)))); err != nil {
		t.Fatal(err)
	}
	if cspTestRead(t, f, queued.ID).Command.Phase != "acknowledged" {
		t.Fatal("pre-upgrade delivery could not finish")
	}
}
