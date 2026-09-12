package windows

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncMLStoreFixture struct {
	store       *Store
	identity    ManagementDeviceIdentity
	certificate *x509.Certificate
	options     EnrollmentOptions
	secrets     *syncMLBootstrapSecrets
}

func syncMLTestStore(t *testing.T) syncMLStoreFixture {
	t.Helper()
	s := authorityTestStore(t)
	initializeTestAuthority(t, s, 1)
	options := enrollmentTestOptions()
	_, result, _ := managementTestEnrollment(t, s, options)
	return syncMLTestEnrolled(t, s, result, options)
}

func syncMLTestEnrolled(t *testing.T, s *Store, result enrollmentTestResult, options EnrollmentOptions) syncMLStoreFixture {
	t.Helper()
	request := managementTestRequest(t, result.Certificate, options)
	identity, err := s.AuthenticateManagementDevice(request, options)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	secrets, err := s.syncMLBootstrap(context.Background(), tx, *identity, options)
	if err != nil {
		t.Fatal(err)
	}
	return syncMLStoreFixture{s, *identity, request.TLS.PeerCertificates[0], options, secrets}
}

func (f syncMLStoreFixture) process(data []byte) ([]byte, error) {
	return f.store.processSyncML(context.Background(), f.certificate, data, f.options)
}

func (f syncMLStoreFixture) initial(t *testing.T) []byte {
	t.Helper()
	return syncMLTestWire(t, syncMLTestInitial(f.identity, f.options, f.secrets))
}

func (f syncMLStoreFixture) state(t *testing.T) (*syncMLDeviceRecord, *syncMLSession) {
	t.Helper()
	tx, err := f.store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	record, err := f.store.lockSyncMLDevice(context.Background(), tx, f.identity, f.options, f.secrets)
	if err != nil {
		t.Fatal(err)
	}
	session, err := f.store.lockSyncMLSession(context.Background(), tx, f.identity, f.options, record.ActiveSessionID)
	if err != nil {
		t.Fatal(err)
	}
	return record, session
}

func syncMLTestCounts(t *testing.T, s *Store, state, sessions, packets, audits int) {
	t.Helper()
	for table, want := range map[string]int{"mdm_windows_syncml_state": state, "mdm_windows_syncml_sessions": sessions, "mdm_windows_syncml_packets": packets, "mdm_windows_management_audit": audits} {
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != want {
			t.Fatal("unexpected management row count", table, count, want, err)
		}
	}
}

func TestSyncMLStoreConcurrentReplayRestartAndSessionIDReuse(t *testing.T) {
	f := syncMLTestStore(t)
	initial := f.initial(t)
	type result struct {
		data []byte
		err  error
	}
	results := make(chan result, 8)
	var workers sync.WaitGroup
	for n := 0; n < 8; n++ {
		workers.Add(1)
		go func() { defer workers.Done(); data, err := f.process(initial); results <- result{data, err} }()
	}
	workers.Wait()
	close(results)
	var first []byte
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if first == nil {
			first = result.data
		} else if !bytes.Equal(first, result.data) {
			t.Fatal("concurrent retry changed the committed response")
		}
	}
	syncMLTestCounts(t, f.store, 1, 1, 1, 8)
	record, session := f.state(t)
	if record.Revision != 2 || session.Revision != 1 || session.LastMessage != 1 || session.Phase != "authenticating" {
		t.Fatal("replay advanced durable session state")
	}
	restarted, err := NewStoreWithMasterKey(f.store.db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	f.store = restarted
	if replay, err := f.process(initial); err != nil || !bytes.Equal(replay, first) {
		t.Fatal("process restart changed exact replay", err)
	}
	reply := syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))
	final, err := f.process(reply)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := f.process(reply); err != nil || !bytes.Equal(replay, final) {
		t.Fatal("completed exchange replay failed", err)
	}
	syncMLTestCounts(t, f.store, 1, 1, 2, 12)
	record, session = f.state(t)
	if session.Phase != "completed" || session.State.Probe.Status != "200" || !session.State.Probe.HasResult {
		t.Fatal("authenticated result was not durable")
	}
	if _, err := f.process(append([]byte("\n"), initial...)); !errors.Is(err, ErrSyncMLReplay) {
		t.Fatal("same message ID accepted different bytes", err)
	}
	nextSecrets := *f.secrets
	nextSecrets.ClientNonce = record.Nonces.ClientNonce
	next := syncMLTestWire(t, syncMLTestInitial(f.identity, f.options, &nextSecrets))
	newResponse, err := f.process(next)
	if err != nil {
		t.Fatal("current nonce could not start reused wire session", err)
	}
	_, newSession := f.state(t)
	if newSession.ID == session.ID || bytes.Equal(first, newResponse) {
		t.Fatal("reused wire ID reused the old server session")
	}
	if response, err := f.process(reply); err == nil || response != nil {
		t.Fatal("old result acknowledged the new session")
	}
	newReply := syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, newResponse)))
	if _, err := f.process(newReply); err != nil {
		t.Fatal("fresh correlated result rejected", err)
	}
	syncMLTestCounts(t, f.store, 1, 2, 4, 15)
	// Nonces, device hints and response XML stay inside AEAD ciphertext.
	for _, table := range []string{"mdm_windows_syncml_state", "mdm_windows_syncml_sessions", "mdm_windows_syncml_packets", "mdm_windows_management_audit"} {
		rows, err := f.store.db.Query(`SELECT row_to_json(t)::text FROM ` + table + ` t`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{f.secrets.ClientSecret, f.secrets.ServerSecret, record.Nonces.ClientNonce, "synthetic-device", "<SyncML"} {
				if strings.Contains(value, secret) {
					t.Fatal("management persistence exposed plaintext", table)
				}
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
}

func TestSyncMLStoreRollbackOnAuditSizeAndCancellation(t *testing.T) {
	f := syncMLTestStore(t)
	initial := syncMLTestInitial(f.identity, f.options, f.secrets)
	tooSmall := uint64(1)
	initial.Header.Meta.MaxMessageSize = &tooSmall
	if data, err := f.process(syncMLTestWire(t, initial)); !errors.Is(err, ErrSyncMLMessageSize) || data != nil {
		t.Fatal("negotiated response bound released bytes", err)
	}
	syncMLTestCounts(t, f.store, 0, 0, 0, 0)
	_, err := f.store.db.Exec(`CREATE FUNCTION reject_syncml_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic management audit failure'; END; $$; CREATE TRIGGER reject_syncml_audit BEFORE INSERT ON mdm_windows_management_audit FOR EACH ROW EXECUTE FUNCTION reject_syncml_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	initialData := f.initial(t)
	if data, err := f.process(initialData); err == nil || data != nil {
		t.Fatal("failed audit returned a management response")
	}
	syncMLTestCounts(t, f.store, 0, 0, 0, 0)
	if _, err := f.store.db.Exec(`DROP TRIGGER reject_syncml_audit ON mdm_windows_management_audit`); err != nil {
		t.Fatal(err)
	}
	first, err := f.process(initialData)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`CREATE TRIGGER reject_syncml_audit BEFORE INSERT ON mdm_windows_management_audit FOR EACH ROW EXECUTE FUNCTION reject_syncml_audit()`); err != nil {
		t.Fatal(err)
	}
	if data, err := f.process(initialData); err == nil || data != nil {
		t.Fatal("failed replay audit returned stored response")
	}
	if data, err := f.process(syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))); err == nil || data != nil {
		t.Fatal("failed completion audit advanced session")
	}
	syncMLTestCounts(t, f.store, 1, 1, 1, 1)
	_, session := f.state(t)
	if session.LastMessage != 1 || session.Phase != "authenticating" {
		t.Fatal("failed audit changed protected session")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if data, err := f.store.processSyncML(ctx, f.certificate, initialData, f.options); err == nil || data != nil {
		t.Fatal("canceled transaction returned management response")
	}
}

func TestSyncMLStoreChallengeSurvivesRestart(t *testing.T) {
	f := syncMLTestStore(t)
	first := syncMLTestInitial(f.identity, f.options, f.secrets)
	first.Header.Credential = nil
	initial := syncMLTestWire(t, first)
	challenge, err := f.process(initial)
	if err != nil {
		t.Fatal(err)
	}
	response := syncMLTestParsed(t, challenge)
	if response.Commands[0].Data.Text != "407" {
		t.Fatal("missing digest did not produce a challenge")
	}
	store, err := NewStoreWithMasterKey(f.store.db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	f.store = store
	if replay, err := f.process(initial); err != nil || !bytes.Equal(replay, challenge) {
		t.Fatal("restart lost the challenge nonce", err)
	}
	retry := syncMLTestInitial(f.identity, f.options, f.secrets)
	retry.Header.MessageID = "2"
	retry.Header.Credential.Digest, err = syncMLDigest(f.identity.DeviceID, f.secrets.ClientSecret, response.Commands[0].Challenge.NextNonce)
	if err != nil {
		t.Fatal(err)
	}
	syncMLStatus(retry, "1", "0", "SyncHdr", "212")
	probe, err := f.process(syncMLTestWire(t, retry))
	if err != nil {
		t.Fatal("durable challenge did not authenticate", err)
	}
	if _, err := f.process(syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, probe)))); err != nil {
		t.Fatal(err)
	}
	syncMLTestCounts(t, f.store, 1, 1, 3, 5)
	record, session := f.state(t)
	if record.Nonces.ClientNonce == response.Commands[0].Challenge.NextNonce || session.Phase != "completed" {
		t.Fatal("challenge retry failed to rotate the next-session nonce")
	}
}

func TestSyncMLStoreCancellationWhileStateIsLocked(t *testing.T) {
	f := syncMLTestStore(t)
	initial := f.initial(t)
	if _, err := f.process(initial); err != nil {
		t.Fatal(err)
	}
	hold, err := f.store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	var pid int
	if err := hold.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := hold.Exec(`SELECT device_id FROM mdm_windows_syncml_state FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		data, err := f.store.processSyncML(ctx, f.certificate, initial, f.options)
		if data != nil {
			err = errors.New("canceled replay returned response bytes")
		}
		finished <- err
	}()
	waitForCredentialLock(t, f.store.db, pid, 1)
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("queued session ignored cancellation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled session did not release its transaction")
	}
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	syncMLTestCounts(t, f.store, 1, 1, 1, 1)
	if _, err := f.process(initial); err != nil {
		t.Fatal("cancellation damaged replay state", err)
	}
}

func TestSyncMLStoreScopeRevocationAndWrongKey(t *testing.T) {
	for name, change := range map[string]func(*testing.T, syncMLStoreFixture){
		"certificate revoked": func(t *testing.T, f syncMLStoreFixture) {
			if _, err := f.store.db.Exec(`UPDATE mdm_windows_device_certificates SET revoked_at=clock_timestamp() WHERE id=$1`, f.identity.CertificateID); err != nil {
				t.Fatal(err)
			}
		},
		"device revoked": func(t *testing.T, f syncMLStoreFixture) {
			if _, err := f.store.db.Exec(`UPDATE mdm_windows_devices SET revoked_at=clock_timestamp() WHERE id=$1`, f.identity.DeviceID); err != nil {
				t.Fatal(err)
			}
		},
		"site moved": func(t *testing.T, f syncMLStoreFixture) {
			if _, err := f.store.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=11`); err != nil {
				t.Fatal(err)
			}
		},
		"wrong encryption key": func(t *testing.T, f syncMLStoreFixture) {
			other, _ := newSyncMLNonce()
			box, err := newAuthoritySecretBox(other)
			if err != nil {
				t.Fatal(err)
			}
			f.store.secrets = box
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := syncMLTestStore(t)
			initial := f.initial(t)
			first, err := f.process(initial)
			if err != nil {
				t.Fatal(err)
			}
			change(t, f)
			for _, data := range [][]byte{initial, syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))} {
				if response, err := f.process(data); err == nil || response != nil {
					t.Fatal("changed authorization released a response")
				}
			}
			syncMLTestCounts(t, f.store, 1, 1, 1, 1)
		})
	}
}

func TestSyncMLStoreImmutableScopedHistoryAndCiphertextBinding(t *testing.T) {
	f := syncMLTestStore(t)
	initial := f.initial(t)
	if _, err := f.process(initial); err != nil {
		t.Fatal(err)
	}
	_, session := f.state(t)
	for _, statement := range []string{
		`UPDATE mdm_windows_syncml_state SET revision=revision+1,site_id=12`,
		`UPDATE mdm_windows_syncml_state SET revision=revision+2`,
		`UPDATE mdm_windows_syncml_sessions SET revision=revision+1,last_message=last_message+2`,
		`UPDATE mdm_windows_syncml_sessions SET revision=revision+1,expires_at=expires_at+INTERVAL '1 second'`,
		`UPDATE mdm_windows_syncml_packets SET request_digest=response_digest`,
		`UPDATE mdm_windows_management_audit SET action='session.completed'`,
		`DELETE FROM mdm_windows_syncml_state`,
		`DELETE FROM mdm_windows_syncml_sessions`,
		`DELETE FROM mdm_windows_syncml_packets`,
		`DELETE FROM mdm_windows_management_audit`,
		`INSERT INTO mdm_windows_management_audit(device_id,tenant_id,site_id,session_id,action) SELECT device_id,tenant_id,12,session_id,'session.completed' FROM mdm_windows_management_audit LIMIT 1`,
		`INSERT INTO mdm_windows_syncml_packets(session_id,device_id,tenant_id,site_id,message_id,request_digest,response_digest,encrypted_response) SELECT session_id,device_id,tenant_id,12,2,request_digest,response_digest,encrypted_response FROM mdm_windows_syncml_packets`,
	} {
		if _, err := f.store.db.Exec(statement); err == nil {
			t.Fatal("database accepted management history or scope mutation")
		}
	}
	// Changing a valid revision without re-encrypting its state must not make
	// the old ciphertext valid under the new metadata.
	if _, err := f.store.db.Exec(`UPDATE mdm_windows_syncml_state SET revision=revision+1`); err != nil {
		t.Fatal(err)
	}
	if response, err := f.process(initial); !errors.Is(err, ErrAuthoritySecret) || response != nil {
		t.Fatal("nonce ciphertext was not bound to its revision", err)
	}
	if session.ID == "" {
		t.Fatal("missing fixture session")
	}
}

// This fixture only modifies an isolated, randomly named test schema. It makes
// short expiry tests possible without a 15-minute sleep and authenticates the
// changed metadata with the owned test key before restoring the normal trigger.
func syncMLTestExpiry(t *testing.T, f syncMLStoreFixture, expiry time.Time) {
	t.Helper()
	_, session := f.state(t)
	session.ExpiresAt = expiry.UTC().Truncate(time.Microsecond)
	encrypted, err := f.store.sealSyncMLJSON(session.State, syncMLSessionPurpose("session", f.identity, f.options, session, session.Revision), maxSyncMLSessionStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE mdm_windows_syncml_sessions DISABLE TRIGGER mdm_windows_syncml_session_identity`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE mdm_windows_syncml_sessions SET expires_at=$2,encrypted_state=$3 WHERE id=$1`, session.ID, session.ExpiresAt, encrypted); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`ALTER TABLE mdm_windows_syncml_sessions ENABLE TRIGGER mdm_windows_syncml_session_identity`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestSyncMLStoreExpiryAfterAuditAndStateLock(t *testing.T) {
	for _, auditWait := range []bool{false, true} {
		t.Run(map[bool]string{false: "device state lock", true: "completion audit"}[auditWait], func(t *testing.T) {
			f := syncMLTestStore(t)
			first, err := f.process(f.initial(t))
			if err != nil {
				t.Fatal(err)
			}
			var now time.Time
			if err := f.store.db.QueryRow(`SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			expires := now.Add(500 * time.Millisecond)
			syncMLTestExpiry(t, f, expires)
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
			if auditWait {
				if _, err := hold.Exec(`LOCK TABLE mdm_windows_management_audit IN SHARE MODE`); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := hold.Exec(`SELECT device_id FROM mdm_windows_syncml_state FOR UPDATE`); err != nil {
					t.Fatal(err)
				}
			}
			finished := make(chan error, 1)
			request := syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))
			go func() {
				data, err := f.store.processSyncML(ctx, f.certificate, request, f.options)
				if data != nil {
					err = errors.New("response escaped after session expiry")
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
			if err := <-finished; !errors.Is(err, ErrSyncMLSessionExpired) {
				t.Fatal("session expiry was not rechecked after a wait", err)
			}
			syncMLTestCounts(t, f.store, 1, 1, 1, 1)
			if response, err := f.process(f.initial(t)); !errors.Is(err, ErrSyncMLSessionExpired) || response != nil {
				t.Fatal("expired packet was replayed", err)
			}
			// A different wire session can replace the expired one. The expiry
			// transition and the new session commit together with fresh command IDs.
			record, _ := f.state(t)
			secrets := *f.secrets
			secrets.ClientNonce = record.Nonces.ClientNonce
			next := syncMLTestInitial(f.identity, f.options, &secrets)
			next.Header.SessionID = "2"
			if _, err := f.process(syncMLTestWire(t, next)); err != nil {
				t.Fatal("expired session prevented a new exchange", err)
			}
			syncMLTestCounts(t, f.store, 1, 2, 2, 3)
		})
	}
}

func TestSyncMLStoreBootstrapAndActiveSessionCannotBeReassigned(t *testing.T) {
	f := syncMLTestStore(t)
	initial := f.initial(t)
	first, err := f.process(initial)
	if err != nil {
		t.Fatal(err)
	}
	_, otherResult, _ := managementTestEnrollment(t, f.store, f.options)
	other := syncMLTestEnrolled(t, f.store, otherResult, f.options)
	if _, err := other.process(initial); err != nil {
		t.Fatal("expected bounded challenge for another certificate", err)
	}
	_, otherSession := other.state(t)
	if otherSession.State.ClientAuthenticated || len(otherSession.State.DeviceInfo) != 0 {
		t.Fatal("another certificate reused the first device bootstrap")
	}
	if _, err := f.store.db.Exec(`UPDATE mdm_windows_syncml_state SET revision=revision+1,active_session_id=$2 WHERE device_id=$1`, f.identity.DeviceID, otherSession.ID); err == nil {
		t.Fatal("active session pointer crossed device identity")
	}
	newWire := syncMLTestInitial(f.identity, f.options, f.secrets)
	newWire.Header.SessionID = "2"
	newWire.Header.Credential = nil
	if response, err := f.process(syncMLTestWire(t, newWire)); !errors.Is(err, ErrSyncMLSession) || response != nil {
		t.Fatal("unauthenticated new session replaced an active exchange", err)
	}
	if _, err := f.process(syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))); err != nil {
		t.Fatal("unrelated rejected request damaged the active session", err)
	}
	// A completed session is terminal even for an otherwise valid revision.
	if _, err := f.store.db.Exec(`UPDATE mdm_windows_syncml_sessions SET revision=revision+1,last_message=last_message+1 WHERE device_id=$1`, f.identity.DeviceID); err == nil {
		t.Fatal("completed session allowed further transitions")
	}
}

func TestSyncMLStoreMigrationPreservesIssuedEnrollment(t *testing.T) {
	base := credentialTestStoreBeforeMigration(t)
	ctx := context.Background()
	tx, err := base.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE mdm_windows_migrations(name TEXT PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"migrations/001_enrollment_credentials.sql", "migrations/002_enrollment_authorities.sql", "migrations/003_device_enrollment.sql"} {
		body, err := migrations.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(string(body)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO mdm_windows_migrations(name) VALUES($1)`, name); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	s, err := NewStoreWithMasterKey(base.db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	initializeTestAuthority(t, s, 1)
	invitation, before, _ := managementTestEnrollment(t, s, enrollmentTestOptions())
	for n := 0; n < 2; n++ {
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	after := readEnrollmentTestResult(t, s, invitation.ID)
	if before.DeviceID != after.DeviceID || before.AuthorityID != after.AuthorityID || !bytes.Equal(before.Certificate, after.Certificate) || !bytes.Equal(before.Auth, after.Auth) || !bytes.Equal(before.Provisioning, after.Provisioning) {
		t.Fatal("session migration changed issued enrollment identity or bootstrap")
	}
	f := syncMLTestEnrolled(t, s, after, enrollmentTestOptions())
	if _, err := f.process(f.initial(t)); err != nil {
		t.Fatal("issued enrollment could not start a session after upgrade", err)
	}
	if invitationEventCount(t, s, invitation.ID, "enrollment.issued") != 1 {
		t.Fatal("session migration altered enrollment audit")
	}
}

func TestSyncMLStoreCorruptedSessionAndResponseFailClosed(t *testing.T) {
	for name, statement := range map[string]string{
		"session revision":   `UPDATE mdm_windows_syncml_sessions SET revision=revision+1,last_message=last_message+1`,
		"session ciphertext": `UPDATE mdm_windows_syncml_sessions SET revision=revision+1,last_message=last_message+1,encrypted_state=set_byte(encrypted_state,20,get_byte(encrypted_state,20)#1)`,
		// Only the owned test schema temporarily disables append-only history
		// to simulate storage corruption; runtime code never does this.
		"response ciphertext": `ALTER TABLE mdm_windows_syncml_packets DISABLE TRIGGER mdm_windows_syncml_packet_history; UPDATE mdm_windows_syncml_packets SET encrypted_response=set_byte(encrypted_response,20,get_byte(encrypted_response,20)#1); ALTER TABLE mdm_windows_syncml_packets ENABLE TRIGGER mdm_windows_syncml_packet_history`,
		"response digest":     `ALTER TABLE mdm_windows_syncml_packets DISABLE TRIGGER mdm_windows_syncml_packet_history; UPDATE mdm_windows_syncml_packets SET response_digest=set_byte(response_digest,0,get_byte(response_digest,0)#1); ALTER TABLE mdm_windows_syncml_packets ENABLE TRIGGER mdm_windows_syncml_packet_history`,
	} {
		t.Run(name, func(t *testing.T) {
			f := syncMLTestStore(t)
			initial := f.initial(t)
			if _, err := f.process(initial); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if data, err := f.process(initial); !errors.Is(err, ErrAuthoritySecret) || data != nil {
				t.Fatal("corrupted protected state returned a response", err)
			}
			syncMLTestCounts(t, f.store, 1, 1, 1, 1)
		})
	}
}
