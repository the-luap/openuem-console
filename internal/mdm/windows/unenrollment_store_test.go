package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func unenrollmentTestMessage(t *testing.T, f syncMLStoreFixture, nonce string) *SyncMLMessage {
	t.Helper()
	secrets := *f.secrets
	secrets.ClientNonce = nonce
	request := syncMLTestInitial(f.identity, f.options, &secrets)
	request.Commands = append(request.Commands, SyncMLCommand{Kind: "Alert", ID: "3", Data: &SyncMLData{Text: "1226"}, Items: []SyncMLItem{{Meta: &SyncMLMeta{Type: windowsUnenrollmentAlertType, Format: "int"}, Data: &SyncMLData{Text: "1"}}}})
	return request
}

func unenrollmentTestCount(t *testing.T, s *Store, table string, want int) {
	t.Helper()
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != want {
		t.Fatal("unexpected unenrollment row count", table, count, want, err)
	}
}

func TestWindowsUnenrollmentFirstNotificationRetiresAccessAndPreservesEvidence(t *testing.T) {
	f := syncMLTestStore(t)
	ctx := context.Background()
	var enrollment string
	if err := f.store.db.QueryRow(`SELECT row_to_json(e)::text FROM mdm_windows_enrollments e`).Scan(&enrollment); err != nil {
		t.Fatal(err)
	}
	request := unenrollmentTestMessage(t, f, f.secrets.ClientNonce)
	data := syncMLTestWire(t, request)
	response, err := f.process(data)
	if err != nil {
		t.Fatal(err)
	}
	reply := syncMLTestParsed(t, response)
	if !reply.Final || reply.Header.MessageID != "1" || reply.Header.SessionID != request.Header.SessionID || reply.Header.Credential == nil || verifySyncMLDigest(f.options.ProviderID, f.secrets.ServerSecret, f.secrets.ServerNonce, reply.Header.Credential.Digest) != nil {
		t.Fatal("notification response lost protocol authentication")
	}
	for _, c := range reply.Commands {
		if c.Kind != "Status" || (c.Data.Text != "200" && c.Data.Text != "212") {
			t.Fatal("notification dispatched management work or rejected its bounded data")
		}
	}
	syncMLTestCounts(t, f.store, 1, 0, 0, 0)
	unenrollmentTestCount(t, f.store, "mdm_windows_unenrollment_reports", 1)
	unenrollmentTestCount(t, f.store, "mdm_windows_unenrollment_audit", 1)
	for _, user := range []string{"admin", "operator", "viewer"} {
		report, err := f.store.UnenrollmentReport(ctx, user, f.identity.Scope, f.identity.DeviceID)
		if err != nil || report.DeviceID != f.identity.DeviceID || report.CertificateID != f.identity.CertificateID || report.FingerprintSHA256 != f.identity.FingerprintSHA256 || report.InterruptedSessionID != "" || report.AlertCommandID != "3" || report.WireSessionID != "1" {
			t.Fatal("scoped report lost authenticated evidence", err)
		}
		encoded, err := json.Marshal(report)
		if err != nil || string(encoded) != "{}" || strings.Contains(fmt.Sprintf("%+v %#v", report, report), report.ID) {
			t.Fatal("generic report formatting disclosed metadata")
		}
	}
	report, err := f.store.Device(ctx, "viewer", f.identity.Scope, f.identity.DeviceID)
	if err != nil || report.RevokedAt == nil || report.UnenrollmentReportedAt == nil || report.Unenrollment == nil || !report.RevokedAt.Equal(report.Unenrollment.ReceivedAt) {
		t.Fatal("device detail lost disconnection meaning", err)
	}
	devices, err := f.store.Devices(ctx, "viewer", f.identity.Scope, "", 0, 10)
	if err != nil || len(devices) != 1 || devices[0].UnenrollmentReportedAt == nil {
		t.Fatal("device list lost disconnection report", err)
	}
	for _, scope := range []access.Scope{{TenantID: 1, SiteID: 12}, {TenantID: 2, SiteID: 21}, {TenantID: 1}} {
		if got, err := f.store.UnenrollmentReport(ctx, "admin", scope, f.identity.DeviceID); err == nil || got != nil {
			t.Fatal("report crossed device scope")
		}
	}
	for _, actor := range []string{"foreign", "missing"} {
		if got, err := f.store.UnenrollmentReport(ctx, actor, f.identity.Scope, f.identity.DeviceID); err == nil || got != nil {
			t.Fatal("report disclosed to foreign actor")
		}
	}
	if got, err := f.store.UnenrollmentReport(ctx, "admin", f.identity.Scope, uuid.NewString()); !errors.Is(err, ErrNotFound) || got != nil {
		t.Fatal("missing report was synthesized", err)
	}
	for _, wire := range [][]byte{data, f.initial(t)} {
		if response, err := f.process(wire); !errors.Is(err, ErrManagementIdentity) || response != nil {
			t.Fatal("retired identity reached replay or management", err)
		}
	}
	if got, err := f.store.AuthenticateManagementDevice(managementTestRequest(t, f.certificate.Raw, f.options), f.options); !errors.Is(err, ErrManagementIdentity) || got != nil {
		t.Fatal("reported disconnection retained transport access", err)
	}
	if err := f.store.RevokeDevice(ctx, "admin", f.identity.Scope, f.identity.DeviceID); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := f.store.db.QueryRow(`SELECT row_to_json(e)::text FROM mdm_windows_enrollments e`).Scan(&after); err != nil || enrollment != after {
		t.Fatal("disconnection rewrote enrollment/bootstrap history", err)
	}
	restarted, err := NewStoreWithMasterKey(f.store.db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.UnenrollmentReport(ctx, "viewer", f.identity.Scope, f.identity.DeviceID); err != nil || !got.ReceivedAt.Equal(report.Unenrollment.ReceivedAt) {
		t.Fatal("restart lost protected disconnection evidence", err)
	}
}

func TestWindowsUnenrollmentInterruptsLiveCSPWithFreshNextSessionProof(t *testing.T) {
	f := syncMLTestStore(t)
	active := cspTestQueue(t, f, cspTestPolicy())
	_, delivery := cspTestStart(t, f)
	queued := cspTestQueue(t, f, cspTestPolicy())
	before, session := f.state(t)
	stale := syncMLTestWire(t, unenrollmentTestMessage(t, f, f.secrets.ClientNonce))
	if response, err := f.process(stale); !errors.Is(err, ErrSyncMLSession) || response != nil {
		t.Fatal("old bootstrap nonce interrupted a live session", err)
	}
	if cspTestRead(t, f, active.ID).Command.Phase != "sent" {
		t.Fatal("rejected notification changed the active command")
	}
	unenrollmentTestCount(t, f.store, "mdm_windows_unenrollment_reports", 0)
	request := unenrollmentTestMessage(t, f, before.Nonces.ClientNonce)
	// The documented first message can reuse a wire session ID, while the
	// current next-session digest distinguishes it from an old packet replay.
	if request.Header.SessionID != session.WireID {
		t.Fatal("fixture did not reuse the active wire session ID")
	}
	if _, err := f.process(syncMLTestWire(t, request)); err != nil {
		t.Fatal(err)
	}
	after, stopped := f.state(t)
	if after.Revision != before.Revision || after.Nonces != before.Nonces || stopped.Phase != "aborted" || stopped.LastMessage != session.LastMessage || stopped.Revision != session.Revision+1 {
		t.Fatal("disconnection reset nonces or invented an old-session packet")
	}
	detail := cspTestRead(t, f, active.ID)
	if detail.Command.Phase != "unknown" || detail.Reason != "session_aborted" || detail.Command.CompletedAt != nil {
		t.Fatal("interrupted device command acquired a false outcome")
	}
	if cspTestRead(t, f, queued.ID).Command.Phase != "queued" {
		t.Fatal("queued command history was rewritten")
	}
	if _, err := f.process(syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, delivery)))); !errors.Is(err, ErrManagementIdentity) {
		t.Fatal("interrupted command accepted a late result", err)
	}
	report, err := f.store.UnenrollmentReport(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID)
	if err != nil || report.InterruptedSessionID != session.ID {
		t.Fatal("interrupted session evidence missing", err)
	}
}

func TestWindowsUnenrollmentAuditFailureRollsBackSessionAndRevocation(t *testing.T) {
	f := syncMLTestStore(t)
	active := cspTestQueue(t, f, cspTestPolicy())
	cspTestStart(t, f)
	before, session := f.state(t)
	data := syncMLTestWire(t, unenrollmentTestMessage(t, f, before.Nonces.ClientNonce))
	if _, err := f.store.db.Exec(`CREATE FUNCTION reject_unenrollment_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic unenrollment audit failure'; END; $$; CREATE TRIGGER reject_unenrollment_audit BEFORE INSERT ON mdm_windows_unenrollment_audit FOR EACH ROW EXECUTE FUNCTION reject_unenrollment_audit()`); err != nil {
		t.Fatal(err)
	}
	if response, err := f.process(data); err == nil || response != nil {
		t.Fatal("failed audit returned an accepted notification")
	}
	unenrollmentTestCount(t, f.store, "mdm_windows_unenrollment_reports", 0)
	after, current := f.state(t)
	if after.Revision != before.Revision || current.Revision != session.Revision || current.Phase != session.Phase || cspTestRead(t, f, active.ID).Command.Phase != "sent" {
		t.Fatal("audit rollback lost active work")
	}
	if device, err := f.store.Device(t.Context(), "viewer", f.identity.Scope, f.identity.DeviceID); err != nil || device.RevokedAt != nil {
		t.Fatal("audit rollback left access revoked", err)
	}
	if _, err := f.store.db.Exec(`DROP TRIGGER reject_unenrollment_audit ON mdm_windows_unenrollment_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.process(data); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`CREATE TRIGGER reject_unenrollment_audit BEFORE INSERT ON mdm_windows_unenrollment_audit FOR EACH ROW EXECUTE FUNCTION reject_unenrollment_audit()`); err != nil {
		t.Fatal(err)
	}
	if report, err := f.store.UnenrollmentReport(t.Context(), "viewer", f.identity.Scope, f.identity.DeviceID); err == nil || report != nil {
		t.Fatal("failed read audit disclosed report")
	}
}

func TestWindowsUnenrollmentConcurrentNotificationsAcceptOnce(t *testing.T) {
	f := syncMLTestStore(t)
	data := syncMLTestWire(t, unenrollmentTestMessage(t, f, f.secrets.ClientNonce))
	results := make(chan error, 8)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			response, err := f.process(data)
			if err == nil && len(response) == 0 {
				err = errors.New("empty success")
			}
			results <- err
		}()
	}
	workers.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrManagementIdentity) {
			t.Fatal(err)
		}
	}
	if accepted != 1 {
		t.Fatal("notification did not retire access atomically", accepted)
	}
	unenrollmentTestCount(t, f.store, "mdm_windows_unenrollment_reports", 1)
	unenrollmentTestCount(t, f.store, "mdm_windows_unenrollment_audit", 1)
}

func TestWindowsUnenrollmentReportAuthenticatesStoredEvidence(t *testing.T) {
	f := syncMLTestStore(t)
	data := syncMLTestWire(t, unenrollmentTestMessage(t, f, f.secrets.ClientNonce))
	if _, err := f.process(data); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`UPDATE mdm_windows_unenrollment_reports SET received_at=received_at+INTERVAL '1 second'`, `DELETE FROM mdm_windows_unenrollment_reports`, `UPDATE mdm_windows_unenrollment_audit SET actor='replacement'`, `DELETE FROM mdm_windows_unenrollment_audit`} {
		if _, err := f.store.db.Exec(statement); err == nil {
			t.Fatal("unenrollment history was mutable")
		}
	}
	var encrypted []byte
	if err := f.store.db.QueryRow(`SELECT encrypted_record FROM mdm_windows_unenrollment_reports`).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(windowsUnenrollmentAlertType)) || bytes.Contains(encrypted, []byte(f.secrets.ClientNonce)) {
		t.Fatal("notification proof stored in plaintext")
	}
	if _, err := f.store.db.Exec(`ALTER TABLE mdm_windows_unenrollment_reports DISABLE TRIGGER mdm_windows_unenrollment_report_history; UPDATE mdm_windows_unenrollment_reports SET encrypted_record=set_byte(encrypted_record,20,get_byte(encrypted_record,20)#1); ALTER TABLE mdm_windows_unenrollment_reports ENABLE TRIGGER mdm_windows_unenrollment_report_history`); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.UnenrollmentReport(t.Context(), "viewer", f.identity.Scope, f.identity.DeviceID); !errors.Is(err, ErrAuthoritySecret) || got != nil {
		t.Fatal("tampered report was trusted", err)
	}
	if got, err := f.store.Device(t.Context(), "viewer", f.identity.Scope, f.identity.DeviceID); !errors.Is(err, ErrAuthoritySecret) || got != nil {
		t.Fatal("device detail disclosed unverified notification", err)
	}
}
