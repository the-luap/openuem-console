package windows

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Only the owned random PostgreSQL test schema uses this fixture. The request
// and result are authenticated again after moving the immutable test deadline.
func cspTestExpiry(t *testing.T, f syncMLStoreFixture, id string, expiry time.Time) {
	t.Helper()
	c, err := scanCSPCommand(f.store.db.QueryRow(`SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE id=$1`, id))
	if err != nil {
		t.Fatal(err)
	}
	request, err := f.store.secrets.openBounded(c.request, cspPurpose("request", c), maxCSPProtectedBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(request)
	var result []byte
	if c.result != nil {
		result, err = f.store.secrets.openBounded(c.result, cspResultPurpose(c), maxCSPProtectedBytes)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(result)
	}
	c.ExpiresAt = expiry.UTC().Truncate(time.Microsecond)
	c.CreatedAt = c.ExpiresAt.Add(-time.Hour)
	c.request, err = f.store.secrets.sealBounded(request, cspPurpose("request", c), maxCSPProtectedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		c.result, err = f.store.secrets.sealBounded(result, cspResultPurpose(c), maxCSPProtectedBytes)
		if err != nil {
			t.Fatal(err)
		}
	}
	tx, err := f.store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE mdm_windows_csp_commands DISABLE TRIGGER mdm_windows_csp_command_identity`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE mdm_windows_csp_commands SET created_at=$2,expires_at=$3,encrypted_request=$4,encrypted_result=$5 WHERE id=$1`, c.ID, c.CreatedAt, c.ExpiresAt, c.request, c.result); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`ALTER TABLE mdm_windows_csp_commands ENABLE TRIGGER mdm_windows_csp_command_identity`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestCSPDeadlineAfterDeliveryAuditWaitAndLateEvidence(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(map[bool]string{false: "new delivery", true: "delivery replay"}[replay], func(t *testing.T) {
			f := syncMLTestStore(t)
			queued := cspTestQueue(t, f, cspTestPolicy())
			first, err := f.process(f.initial(t))
			if err != nil {
				t.Fatal(err)
			}
			request := syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))
			var delivery []byte
			if replay {
				delivery, err = f.process(request)
				if err != nil {
					t.Fatal(err)
				}
			}
			var now time.Time
			if err := f.store.db.QueryRow(`SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			expires := now.Add(500 * time.Millisecond)
			cspTestExpiry(t, f, queued.ID, expires)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			hold, err := f.store.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer hold.Rollback()
			var pid int
			if err := hold.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if _, err := hold.Exec(`LOCK TABLE mdm_windows_management_audit IN SHARE MODE`); err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() {
				data, err := f.store.processSyncML(ctx, f.certificate, request, f.options)
				if data != nil {
					err = errors.New("CSP payload escaped after deadline")
				}
				finished <- err
			}()
			waitForCredentialLock(t, f.store.db, pid, 1)
			if err := waitUntilDatabaseExpiry(ctx, hold, expires); err != nil {
				t.Fatal(err)
			}
			if err := hold.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := <-finished; !errors.Is(err, ErrCSPDeadline) {
				t.Fatal("command deadline was not rechecked before commit", err)
			}
			if replay {
				if _, err := f.process(syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, delivery)))); err != nil {
					t.Fatal("delivery expiry discarded already-executed evidence", err)
				}
				if cspTestRead(t, f, queued.ID).Command.Phase != "acknowledged" {
					t.Fatal("late evidence did not persist")
				}
			} else {
				if cspTestRead(t, f, queued.ID).Command.Phase != "queued" {
					t.Fatal("failed transaction committed delivery metadata")
				}
				if data, err := f.process(request); err != nil || len(syncMLTestParsed(t, data).Commands) != 1 || cspTestRead(t, f, queued.ID).Command.Phase != "expired" {
					t.Fatal("expired intent was not retired without delivery", err)
				}
			}
		})
	}
}

func TestCSPAuditFailureRollsBackIntentAndCancellation(t *testing.T) {
	f := syncMLTestStore(t)
	queued := cspTestQueue(t, f, cspTestPolicy())
	if _, err := f.store.db.Exec(`CREATE FUNCTION reject_csp_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic CSP audit failure'; END; $$; CREATE TRIGGER reject_csp_audit BEFORE INSERT ON mdm_windows_csp_audit FOR EACH ROW EXECUTE FUNCTION reject_csp_audit()`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if command, err := f.store.EnqueueCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, uuid.NewString(), cspTestPolicy(), time.Hour); err == nil || command != nil {
		t.Fatal("unaudited CSP intent escaped")
	}
	if err := f.store.CancelCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, queued.ID, queued.Revision); err == nil {
		t.Fatal("unaudited cancellation succeeded")
	}
	if detail, err := f.store.CSPCommandDetails(ctx, "admin", f.identity.Scope, f.identity.DeviceID, queued.ID); err == nil || detail != nil {
		t.Fatal("unaudited protected payload escaped")
	}
	var count int
	var phase string
	if err := f.store.db.QueryRow(`SELECT count(*),min(phase) FROM mdm_windows_csp_commands`).Scan(&count, &phase); err != nil || count != 1 || phase != "queued" {
		t.Fatal("audit rollback left partial intent", err)
	}
}

func TestCSPProtectedMetadataAndAppendOnlyHistory(t *testing.T) {
	f := syncMLTestStore(t)
	queued := cspTestQueue(t, f, cspTestPolicy())
	request, delivery := cspTestStart(t, f)
	c, err := scanCSPCommand(f.store.db.QueryRow(`SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE id=$1`, queued.ID))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*cspStoredCommand){
		"scope":            func(c *cspStoredCommand) { c.SiteID++ },
		"creator":          func(c *cspStoredCommand) { c.CreatedByRevision++ },
		"deadline":         func(c *cspStoredCommand) { c.ExpiresAt = c.ExpiresAt.Add(time.Second) },
		"request identity": func(c *cspStoredCommand) { c.RequestKey = uuid.NewString() },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *c
			mutate(&changed)
			if plain, _, err := f.store.openCSPRequest(&changed); err == nil || plain != nil {
				t.Fatal("request ciphertext accepted reassigned metadata")
			}
			if _, err := f.store.openCSPResult(&changed); err == nil {
				t.Fatal("result ciphertext accepted reassigned metadata")
			}
		})
	}
	for _, statement := range []string{
		`UPDATE mdm_windows_csp_commands SET revision=revision+1,created_by_revision=created_by_revision+1`,
		`UPDATE mdm_windows_csp_commands SET revision=revision+1,delivered_message=delivered_message+1`,
		`DELETE FROM mdm_windows_csp_commands`,
		`UPDATE mdm_windows_csp_audit SET actor='synthetic-forged-actor'`,
		`DELETE FROM mdm_windows_csp_audit`,
	} {
		if _, err := f.store.db.Exec(statement); err == nil {
			t.Fatal("immutable CSP identity or history was changed")
		}
	}
	if _, err := f.process(syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, delivery)))); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE mdm_windows_csp_commands SET revision=revision+1`,
		`UPDATE mdm_windows_csp_observations SET request_digest=decode(repeat('00',32),'hex')`,
		`DELETE FROM mdm_windows_csp_observations`,
		`INSERT INTO mdm_windows_csp_observations SELECT command_id,device_id,tenant_id,site_id,session_id,20,request_digest,encrypted_observation,created_at FROM mdm_windows_csp_observations`,
	} {
		if _, err := f.store.db.Exec(statement); err == nil {
			t.Fatal("immutable outcome or packet-bound observation was changed")
		}
	}
	if data, err := f.process(request); !errors.Is(err, ErrCSPAlreadySent) || data != nil {
		t.Fatal("terminal history checks reopened execution", err)
	}
}

func TestCSPMigrationPreservesExistingSessions(t *testing.T) {
	f := syncMLTestStore(t)
	initial := f.initial(t)
	response, err := f.process(initial)
	if err != nil {
		t.Fatal(err)
	}
	// Removing only the empty CSP extension produces the previous migration's
	// schema while retaining issued enrollment, nonce state and encrypted packet.
	unenrollmentTestRemoveRequestMigration(t, f.store)
	updateTestRemoveRingMigration(t, f.store)
	renewalTestRemoveMigration(t, f.store)
	if _, err := f.store.db.Exec(`DROP TABLE mdm_windows_update_audit,mdm_windows_csp_observations,mdm_windows_csp_audit,mdm_windows_csp_commands,mdm_windows_update_runs; DROP FUNCTION mdm_windows_keep_csp_command(); ALTER TABLE mdm_windows_syncml_packets DROP CONSTRAINT mdm_windows_syncml_packet_scope_message; DELETE FROM mdm_windows_migrations WHERE name IN ('migrations/005_csp_commands.sql','migrations/006_update_runs.sql','migrations/007_update_verification_batches.sql')`); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		if err := f.store.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if replay, err := f.process(initial); err != nil || !bytes.Equal(replay, response) {
		t.Fatal("CSP migration changed an existing encrypted exchange", err)
	}
	cspTestQueue(t, f, cspTestPolicy())
	if delivery, err := f.process(syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, response)))); err != nil || len(syncMLTestParsed(t, delivery).Commands) != 2 {
		t.Fatal("upgraded session could not deliver queued intent", err)
	}
}

func TestCSPCorruptedResultRejectsDeliveryAndMetadataReads(t *testing.T) {
	for _, statement := range []string{
		`UPDATE mdm_windows_csp_commands SET revision=revision+1`,
		`UPDATE mdm_windows_csp_commands SET revision=revision+1,encrypted_result=set_byte(encrypted_result,20,get_byte(encrypted_result,20)#1)`,
	} {
		f := syncMLTestStore(t)
		queued := cspTestQueue(t, f, cspTestPolicy())
		request, delivery := cspTestStart(t, f)
		if _, err := f.store.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if value, err := f.store.CSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, queued.ID); !errors.Is(err, ErrAuthoritySecret) || value != nil {
			t.Fatal("corrupted command exposed unauthenticated metadata", err)
		}
		if list, err := f.store.CSPCommands(ctx, "admin", f.identity.Scope, f.identity.DeviceID, 0, 100); !errors.Is(err, ErrAuthoritySecret) || list != nil {
			t.Fatal("corrupted command exposed a status listing", err)
		}
		if value, err := f.store.CSPCommandDetails(ctx, "admin", f.identity.Scope, f.identity.DeviceID, queued.ID); !errors.Is(err, ErrAuthoritySecret) || value != nil {
			t.Fatal("corrupted command exposed protected details", err)
		}
		for _, data := range [][]byte{request, syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, delivery)))} {
			if result, err := f.process(data); !errors.Is(err, ErrAuthoritySecret) || result != nil {
				t.Fatal("corrupted result permitted delivery or progress", err)
			}
		}
	}
}
