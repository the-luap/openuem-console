package windows

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestWindowsUnenrollmentRequestCreatorRevisionAndConfiguration(t *testing.T) {
	for _, sent := range []bool{false, true} {
		t.Run(fmt.Sprint("sent_", sent), func(t *testing.T) {
			f := syncMLTestStore(t)
			ctx := t.Context()
			principal, err := f.store.permissions.Principal(ctx, "second")
			if err != nil {
				t.Fatal(err)
			}
			grants := []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}
			if err = f.store.permissions.ReplaceGrants(ctx, "admin", "second", principal.Revision, grants); err != nil {
				t.Fatal(err)
			}
			altered := f.options
			altered.ProviderID = "OtherProvider"
			if c, err := f.store.EnqueueUnenrollmentRequest(ctx, "second", f.identity.Scope, f.identity.DeviceID, uuid.NewString(), "Retire device", time.Hour, altered); !errors.Is(err, ErrAuthoritySecret) || c != nil {
				t.Fatal("unbound provider accepted", err)
			}
			unenrollmentTestCount(t, f.store, "mdm_windows_unenrollment_requests", 0)
			key := uuid.NewString()
			c, err := f.store.EnqueueUnenrollmentRequest(ctx, "second", f.identity.Scope, f.identity.DeviceID, key, "Retire device", time.Hour, f.options)
			if err != nil {
				t.Fatal(err)
			}
			var request, delivery []byte
			if sent {
				request, delivery = cspTestStart(t, f)
			}
			principal, err = f.store.permissions.Principal(ctx, "second")
			if err != nil {
				t.Fatal(err)
			}
			if err = f.store.permissions.ReplaceGrants(ctx, "admin", "second", principal.Revision, grants); err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.EnqueueUnenrollmentRequest(ctx, "second", f.identity.Scope, f.identity.DeviceID, key, "Retire device", time.Hour, f.options); !errors.Is(err, ErrCSPConflict) {
				t.Fatal("new authority replayed old intent", err)
			}
			if sent {
				if data, err := f.process(request); !errors.Is(err, access.ErrDenied) || data != nil {
					t.Fatal("old authority replayed delivered disconnection", err)
				}
				if _, err = f.process(syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, delivery)))); err != nil {
					t.Fatal("authority change discarded device evidence", err)
				}
				if unenrollmentRequestTestRead(t, f, c.ID).Command.Phase != "acknowledged" {
					t.Fatal("late evidence missing")
				}
			} else {
				_, delivery = cspTestStart(t, f)
				if len(syncMLTestParsed(t, delivery).Commands) != 1 || unenrollmentRequestTestRead(t, f, c.ID).Command.Phase != "canceled" {
					t.Fatal("old authority dispatched disconnection")
				}
			}
		})
	}
}

func TestWindowsUnenrollmentRequestMayFollowUncertainCustomCommand(t *testing.T) {
	f := syncMLTestStore(t)
	normal := cspTestQueue(t, f, cspTestPolicy())
	_, delivery := cspTestStart(t, f)
	reply := cspTestReply(syncMLTestParsed(t, delivery))
	reply.Commands[1].Data.Text = "202"
	if _, err := f.process(syncMLTestWire(t, reply)); err != nil {
		t.Fatal(err)
	}
	before := cspTestRead(t, f, normal.ID)
	queued := unenrollmentRequestTestQueue(t, f)
	next := syncMLTestParsed(t, cspTestNextSession(t, f))
	if len(next.Commands) != 2 || next.Commands[1].Kind != "Exec" || unenrollmentRequestTestRead(t, f, queued.ID).Command.Phase != "sent" {
		t.Fatal("unrelated uncertainty prevented authenticated disconnection delivery")
	}
	after := cspTestRead(t, f, normal.ID)
	if before.Command.Phase != "unknown" || after.Command.Revision != before.Command.Revision || after.Outcomes[0].Status != 202 {
		t.Fatal("disconnection rewrote unrelated uncertainty")
	}
}

func TestWindowsUnenrollmentRequestAuditFailureIsAtomic(t *testing.T) {
	for _, action := range []string{"create", "read", "cancel", "release"} {
		t.Run(action, func(t *testing.T) {
			f := syncMLTestStore(t)
			var c *CSPCommand
			var before *UnenrollmentRequestDetail
			if action != "create" {
				c = unenrollmentRequestTestQueue(t, f)
				if action == "release" {
					cspTestStart(t, f)
				}
				before = unenrollmentRequestTestRead(t, f, c.ID)
			}
			if _, err := f.store.db.Exec(`CREATE FUNCTION reject_unenrollment_request_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic disconnection audit failure'; END; $$; CREATE TRIGGER reject_unenrollment_request_audit BEFORE INSERT ON mdm_windows_unenrollment_request_audit FOR EACH ROW EXECUTE FUNCTION reject_unenrollment_request_audit()`); err != nil {
				t.Fatal(err)
			}
			var err error
			switch action {
			case "create":
				c, err = f.store.EnqueueUnenrollmentRequest(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, uuid.NewString(), "Retire device", time.Hour, f.options)
				if c != nil {
					t.Fatal("failed transaction exposed intent")
				}
			case "read":
				var detail *UnenrollmentRequestDetail
				detail, err = f.store.UnenrollmentRequestDetails(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, c.ID)
				if detail != nil {
					t.Fatal("failed audit exposed intent")
				}
			case "cancel":
				err = f.store.CancelUnenrollmentRequest(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, c.ID, before.Command.Revision)
			case "release":
				err = f.store.ReleaseUnenrollmentRequest(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, c.ID, before.Command.Revision, "Investigated uncertainty")
			}
			if err == nil {
				t.Fatal("audit failure accepted")
			}
			if _, err = f.store.db.Exec(`DROP TRIGGER reject_unenrollment_request_audit ON mdm_windows_unenrollment_request_audit`); err != nil {
				t.Fatal(err)
			}
			if action == "create" {
				unenrollmentTestCount(t, f.store, "mdm_windows_unenrollment_requests", 0)
				unenrollmentTestCount(t, f.store, "mdm_windows_csp_commands", 0)
			} else {
				after := unenrollmentRequestTestRead(t, f, c.ID)
				if after.Command.Revision != before.Command.Revision || after.Command.Phase != before.Command.Phase || after.Release != nil {
					t.Fatal("failed audit partially committed state")
				}
				if action == "release" {
					_, session := f.state(t)
					if session.Phase != "active" {
						t.Fatal("failed release aborted live session")
					}
				}
			}
		})
	}
}

func TestWindowsUnenrollmentRequestImmutableOwnerAndProtectedIntent(t *testing.T) {
	f := syncMLTestStore(t)
	c := unenrollmentRequestTestQueue(t, f)
	for _, statement := range []string{
		`UPDATE mdm_windows_csp_commands SET unenrollment_request_id=NULL,revision=revision+1`,
		`UPDATE mdm_windows_unenrollment_requests SET created_by='operator'`,
		`DELETE FROM mdm_windows_unenrollment_requests`,
		`DELETE FROM mdm_windows_unenrollment_request_audit`,
	} {
		if _, err := f.store.db.Exec(statement); err == nil {
			t.Fatal("immutable lifecycle ownership changed")
		}
	}
	_, delivery := cspTestStart(t, f)
	before := unenrollmentRequestTestRead(t, f, c.ID)
	if err := f.store.ReleaseUnenrollmentRequest(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, c.ID, before.Command.Revision, "Investigated; allow new work"); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`UPDATE mdm_windows_unenrollment_releases SET released_by='operator'`, `DELETE FROM mdm_windows_unenrollment_releases`} {
		if _, err := f.store.db.Exec(statement); err == nil {
			t.Fatal("immutable lifecycle review changed")
		}
	}
	// Only the owned disposable schema bypasses triggers to model storage damage.
	if _, err := f.store.db.Exec(`ALTER TABLE mdm_windows_unenrollment_releases DISABLE TRIGGER mdm_windows_unenrollment_release_history; UPDATE mdm_windows_unenrollment_releases SET encrypted_reason=set_byte(encrypted_reason,20,get_byte(encrypted_reason,20)#1); ALTER TABLE mdm_windows_unenrollment_releases ENABLE TRIGGER mdm_windows_unenrollment_release_history`); err != nil {
		t.Fatal(err)
	}
	if d, err := f.store.UnenrollmentRequestDetails(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, c.ID); !errors.Is(err, ErrAuthoritySecret) || d != nil {
		t.Fatal("corrupt review exposed trusted details", err)
	}
	if list, err := f.store.UnenrollmentRequests(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, 0, 10); !errors.Is(err, ErrAuthoritySecret) || list != nil {
		t.Fatal("corrupt review exposed trusted history", err)
	}
	record, _ := f.state(t)
	secrets := *f.secrets
	secrets.ClientNonce = record.Nonces.ClientNonce
	initial := syncMLTestInitial(f.identity, f.options, &secrets)
	initial.Header.SessionID = "2"
	first, err := f.process(syncMLTestWire(t, initial))
	if err != nil {
		t.Fatal(err)
	}
	cspTestQueue(t, f, cspTestPolicy())
	if data, err := f.process(syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))); !errors.Is(err, ErrAuthoritySecret) || data != nil {
		t.Fatal("corrupt review reopened command delivery", err)
	}
	if data, err := f.process(syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, delivery)))); err == nil || data != nil {
		t.Fatal("aborted exchange accepted after review corruption")
	}
}

func TestWindowsUnenrollmentRequestMigrationPreservesUpdateOwnedCiphertext(t *testing.T) {
	f := syncMLTestStore(t)
	zero := 0
	run := updateTestQueue(t, f, UpdatePolicy{QualityDeferralDays: &zero}, false)
	request, delivery := cspTestStart(t, f)
	unenrollmentTestRemoveRequestMigration(t, f.store)
	for n := 0; n < 2; n++ {
		if err := f.store.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if replay, err := f.process(request); err != nil || !bytes.Equal(replay, delivery) {
		t.Fatal("lifecycle migration changed update delivery replay", err)
	}
	if _, err := f.process(syncMLTestWire(t, updateTestReply(syncMLTestParsed(t, delivery), UpdatePolicy{QualityDeferralDays: &zero}, false, false))); err != nil {
		t.Fatal("existing update result failed after migration", err)
	}
	if updateTestRead(t, f, run.ID).Steps[0].Phase != "acknowledged" {
		t.Fatal("upgrade lost update evidence")
	}
}

// Adjust only an owned synthetic request to test final delivery deadlines without
// waiting a minute. Both immutable records and their ciphertext remain bound.
func unenrollmentRequestTestExpiry(t *testing.T, f syncMLStoreFixture, id string, expiry time.Time) {
	t.Helper()
	c, err := scanCSPCommand(f.store.db.QueryRow(`SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE id=$1`, id))
	if err != nil {
		t.Fatal(err)
	}
	var encrypted []byte
	if err = f.store.db.QueryRow(`SELECT encrypted_intent FROM mdm_windows_unenrollment_requests WHERE id=$1`, id).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	intent, err := f.store.secrets.openBounded(encrypted, unenrollmentRequestPurpose(c), maxUnenrollmentIntentBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(intent)
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
	encrypted, err = f.store.secrets.sealBounded(intent, unenrollmentRequestPurpose(c), maxUnenrollmentIntentBytes)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.store.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`ALTER TABLE mdm_windows_csp_commands ALTER CONSTRAINT mdm_windows_csp_unenrollment_request DEFERRABLE INITIALLY DEFERRED; ALTER TABLE mdm_windows_csp_commands DISABLE TRIGGER mdm_windows_csp_command_identity; ALTER TABLE mdm_windows_unenrollment_requests DISABLE TRIGGER mdm_windows_unenrollment_request_history`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE mdm_windows_csp_commands SET created_at=$2,expires_at=$3,encrypted_request=$4,encrypted_result=$5 WHERE id=$1`, c.ID, c.CreatedAt, c.ExpiresAt, c.request, c.result); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE mdm_windows_unenrollment_requests SET created_at=$2,expires_at=$3,encrypted_intent=$4 WHERE id=$1`, c.ID, c.CreatedAt, c.ExpiresAt, encrypted); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`SET CONSTRAINTS ALL IMMEDIATE; ALTER TABLE mdm_windows_csp_commands ENABLE TRIGGER mdm_windows_csp_command_identity; ALTER TABLE mdm_windows_unenrollment_requests ENABLE TRIGGER mdm_windows_unenrollment_request_history; ALTER TABLE mdm_windows_csp_commands ALTER CONSTRAINT mdm_windows_csp_unenrollment_request NOT DEFERRABLE`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsUnenrollmentRequestDeadlineAfterAuditWait(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(fmt.Sprint("replay_", replay), func(t *testing.T) {
			f := syncMLTestStore(t)
			c := unenrollmentRequestTestQueue(t, f)
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
			if err = f.store.db.QueryRow(`SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			expiry := now.Add(600 * time.Millisecond)
			unenrollmentRequestTestExpiry(t, f, c.ID, expiry)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			hold, err := f.store.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer hold.Rollback()
			var pid int
			if err = hold.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if _, err = hold.Exec(`LOCK TABLE mdm_windows_management_audit IN SHARE MODE`); err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() {
				data, err := f.store.processSyncML(ctx, f.certificate, request, f.options)
				if data != nil {
					err = errors.New("expired disconnection payload escaped")
				}
				finished <- err
			}()
			waitForCredentialLock(t, f.store.db, pid, 1)
			if err = waitUntilDatabaseExpiry(ctx, hold, expiry); err != nil {
				t.Fatal(err)
			}
			if err = hold.Commit(); err != nil {
				t.Fatal(err)
			}
			if err = <-finished; !errors.Is(err, ErrCSPDeadline) {
				t.Fatal("final lifecycle delivery deadline was not enforced", err)
			}
			if replay {
				if _, err = f.process(syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, delivery)))); err != nil {
					t.Fatal("deadline discarded delivered evidence", err)
				}
			} else {
				if unenrollmentRequestTestRead(t, f, c.ID).Command.Phase != "queued" {
					t.Fatal("expired transaction committed delivery")
				}
				if data, err := f.process(request); err != nil || len(syncMLTestParsed(t, data).Commands) != 1 || unenrollmentRequestTestRead(t, f, c.ID).Command.Phase != "expired" {
					t.Fatal("expired undelivered intent was not retired", err)
				}
			}
		})
	}
}

func TestWindowsUnenrollmentRequestCorruptIntentAndStrictEvidence(t *testing.T) {
	f := syncMLTestStore(t)
	c := unenrollmentRequestTestQueue(t, f)
	request, delivery := cspTestStart(t, f)
	for _, mutate := range []func(*SyncMLMessage){
		func(m *SyncMLMessage) { m.Commands[1].CommandName = "Replace" },
		func(m *SyncMLMessage) { m.Commands[1].MessageRef = "1" },
		func(m *SyncMLMessage) {
			m.Commands[1].TargetRefs = []string{"./Device/Vendor/MSFT/DMClient/Provider/Other/Unenroll"}
		},
		func(m *SyncMLMessage) {
			m.Commands = append(m.Commands, SyncMLCommand{Kind: "Results", ID: "3", MessageRef: m.Commands[1].MessageRef, CommandRef: m.Commands[1].CommandRef, Items: []SyncMLItem{{Source: &SyncMLLocation{URI: "./Device/Vendor/MSFT/DMClient/Unenroll"}, Data: &SyncMLData{Text: "removed"}}}})
		},
	} {
		reply := cspTestReply(syncMLTestParsed(t, delivery))
		mutate(reply)
		if data, err := f.process(syncMLTestWire(t, reply)); err == nil || data != nil {
			t.Fatal("uncorrelated or fabricated disconnection evidence admitted")
		}
	}
	if unenrollmentRequestTestRead(t, f, c.ID).Command.Phase != "sent" {
		t.Fatal("rejected evidence changed delivery")
	}
	if _, err := f.store.db.Exec(`ALTER TABLE mdm_windows_unenrollment_requests DISABLE TRIGGER mdm_windows_unenrollment_request_history; UPDATE mdm_windows_unenrollment_requests SET encrypted_intent=set_byte(encrypted_intent,20,get_byte(encrypted_intent,20)#1); ALTER TABLE mdm_windows_unenrollment_requests ENABLE TRIGGER mdm_windows_unenrollment_request_history`); err != nil {
		t.Fatal(err)
	}
	if detail, err := f.store.UnenrollmentRequestDetails(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, c.ID); !errors.Is(err, ErrAuthoritySecret) || detail != nil {
		t.Fatal("corrupt intent was trusted", err)
	}
	for _, data := range [][]byte{request, syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, delivery)))} {
		if response, err := f.process(data); !errors.Is(err, ErrAuthoritySecret) || response != nil {
			t.Fatal("corrupt intent allowed replay or new evidence", err)
		}
	}
}

func TestWindowsUnenrollmentRequestHistoryDoesNotConsumeNormalQueueCapacity(t *testing.T) {
	f := syncMLTestStore(t)
	c := unenrollmentRequestTestQueue(t, f)
	cspTestStart(t, f)
	detail := unenrollmentRequestTestRead(t, f, c.ID)
	if err := f.store.ReleaseUnenrollmentRequest(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, c.ID, detail.Command.Revision, "Investigated missing response"); err != nil {
		t.Fatal(err)
	}
	// 249 custom commands and a complete policy must still fit after a
	// released lifecycle command; the historical unknown effect stays intact.
	for n := 0; n < 249; n++ {
		cspTestQueue(t, f, cspTestPolicy())
	}
	zero := 0
	run := updateTestQueue(t, f, UpdatePolicy{QualityDeferralDays: &zero}, false)
	steps := len(updateTestRead(t, f, run.ID).Steps)
	for n := 249 + steps; n < 256; n++ {
		cspTestQueue(t, f, cspTestPolicy())
	}
	if _, err := f.store.EnqueueCSPCommand(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, uuid.NewString(), cspTestPolicy(), time.Hour); !errors.Is(err, ErrCSPQueueFull) {
		t.Fatal("normal queue limit changed", err)
	}
	queued := unenrollmentRequestTestQueue(t, f)
	if queued.Phase != "queued" || unenrollmentRequestTestRead(t, f, c.ID).Command.Phase != "unknown" {
		t.Fatal("lifecycle slot lost or historical uncertainty rewritten")
	}
}
