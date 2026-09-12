package windows

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func unenrollmentTestRemoveRequestMigration(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.Exec(`ALTER TABLE mdm_windows_csp_commands DROP COLUMN unenrollment_request_id; DROP TABLE mdm_windows_unenrollment_request_audit,mdm_windows_unenrollment_releases,mdm_windows_unenrollment_requests; DELETE FROM mdm_windows_migrations WHERE name='migrations/013_unenrollment_requests.sql'`); err != nil {
		t.Fatal(err)
	}
	// Restore the prior trigger body before exercising the old schema.
	migration, err := migrations.ReadFile("migrations/006_update_runs.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(migration), "CREATE OR REPLACE FUNCTION mdm_windows_keep_csp_command()")
	if start < 0 {
		t.Fatal("previous command history function missing")
	}
	function := string(migration)[start:]
	end := strings.Index(function, "$$;")
	if end < 0 {
		t.Fatal("previous function terminator missing")
	}
	if _, err = s.db.Exec(function[:end+3]); err != nil {
		t.Fatal(err)
	}
}

func unenrollmentRequestTestQueue(t *testing.T, f syncMLStoreFixture) *CSPCommand {
	t.Helper()
	c, err := f.store.EnqueueUnenrollmentRequest(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, uuid.NewString(), "Retire this synthetic enrollment <script>review</script>", time.Hour, f.options)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func unenrollmentRequestTestRead(t *testing.T, f syncMLStoreFixture, id string) *UnenrollmentRequestDetail {
	t.Helper()
	detail, err := f.store.UnenrollmentRequestDetails(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, id)
	if err != nil {
		t.Fatal(err)
	}
	return detail
}

func TestWindowsUnenrollmentRequestFixedGrammar(t *testing.T) {
	options := enrollmentTestOptions()
	data, err := encodeUnenrollmentRequest(options)
	if err != nil {
		t.Fatal(err)
	}
	command, err := decodeUnenrollmentRequest(data)
	if err != nil || command.Kind != "Exec" || len(command.Items) != 1 || command.Items[0].Target.URI != "./Device/Vendor/MSFT/DMClient/Unenroll" || command.Items[0].Data.Text != options.ProviderID {
		t.Fatal("fixed request did not round-trip", err)
	}
	for _, spec := range []CSPCommandSpec{{Kind: "Exec", URI: command.Items[0].Target.URI, Format: "chr", Data: &SyncMLData{Text: options.ProviderID}}, {Kind: "Get", URI: command.Items[0].Target.URI}} {
		if _, _, err := encodeCSPRequest(spec); err == nil {
			t.Fatal("custom CSP admitted an enrollment root")
		}
	}
	for _, change := range []func(*SyncMLMessage){
		func(m *SyncMLMessage) { m.Commands[0].Kind = "Replace" },
		func(m *SyncMLMessage) {
			m.Commands[0].Items[0].Target.URI = "./Device/Vendor/MSFT/DMClient/Provider/OpenUEM/Unenroll"
		},
		func(m *SyncMLMessage) { m.Commands[0].Items[0].Data.Text = "../Other" },
		func(m *SyncMLMessage) { m.Commands[0].Items[0].Meta = nil },
		func(m *SyncMLMessage) { m.Commands = append(m.Commands, m.Commands[0]); m.Commands[1].ID = "2" },
		func(m *SyncMLMessage) { m.Header.Source.URI = "urn:other" },
	} {
		message := syncMLTestParsed(t, data)
		change(message)
		encoded, err := EncodeSyncML(message)
		if err != nil {
			continue
		}
		if _, err := decodeUnenrollmentRequest(encoded); !errors.Is(err, ErrAuthoritySecret) {
			t.Fatal("modified lifecycle envelope admitted", err)
		}
	}
}

func TestWindowsUnenrollmentRequestAuthorizationIdempotencyAndCancellation(t *testing.T) {
	f := syncMLTestStore(t)
	ctx := t.Context()
	key := uuid.NewString()
	reason := "Explicit device retirement <script>reason</script>"
	for _, actor := range []string{"operator", "viewer", "foreign", "missing"} {
		if c, err := f.store.EnqueueUnenrollmentRequest(ctx, actor, f.identity.Scope, f.identity.DeviceID, key, reason, time.Hour, f.options); err == nil || c != nil {
			t.Fatal("unprivileged disconnection queued", actor)
		}
	}
	c, err := f.store.EnqueueUnenrollmentRequest(ctx, "admin", f.identity.Scope, f.identity.DeviceID, key, reason, time.Hour, f.options)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 3; n++ {
		old, err := f.store.EnqueueUnenrollmentRequest(ctx, "admin", f.identity.Scope, f.identity.DeviceID, key, reason, time.Hour, f.options)
		if err != nil || old.ID != c.ID {
			t.Fatal("exact retry changed intent", err)
		}
	}
	if _, err = f.store.EnqueueUnenrollmentRequest(ctx, "admin", f.identity.Scope, f.identity.DeviceID, key, reason+" changed", time.Hour, f.options); !errors.Is(err, ErrCSPConflict) {
		t.Fatal("changed retry admitted", err)
	}
	if _, err = f.store.EnqueueUnenrollmentRequest(ctx, "admin", f.identity.Scope, f.identity.DeviceID, uuid.NewString(), reason, time.Hour, f.options); !errors.Is(err, ErrUnenrollmentRequest) {
		t.Fatal("second unresolved request admitted", err)
	}
	if _, err = f.store.EnqueueCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, key, cspTestPolicy(), time.Hour); !errors.Is(err, ErrCSPConflict) {
		t.Fatal("custom request reused lifecycle key", err)
	}
	for _, actor := range []string{"operator", "viewer", "foreign", "missing"} {
		if d, err := f.store.UnenrollmentRequestDetails(ctx, actor, f.identity.Scope, f.identity.DeviceID, c.ID); err == nil || d != nil {
			t.Fatal("unprivileged detail read", actor)
		}
		if d, err := f.store.UnenrollmentRequests(ctx, actor, f.identity.Scope, f.identity.DeviceID, 0, 100); err == nil || d != nil {
			t.Fatal("unprivileged history read", actor)
		}
		if err := f.store.CancelUnenrollmentRequest(ctx, actor, f.identity.Scope, f.identity.DeviceID, c.ID, c.Revision); err == nil {
			t.Fatal("unprivileged cancellation", actor)
		}
	}
	if d, err := f.store.UnenrollmentRequestDetails(ctx, "admin", access.Scope{TenantID: 1, SiteID: 12}, f.identity.DeviceID, c.ID); err == nil || d != nil {
		t.Fatal("cross-site detail read")
	}
	if err = f.store.CancelCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, c.ID, c.Revision); !errors.Is(err, ErrUnenrollmentRequest) {
		t.Fatal("raw CSP canceled lifecycle intent", err)
	}
	if err = f.store.AbandonCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, c.ID, c.Revision, "review"); !errors.Is(err, ErrUnenrollmentRequest) {
		t.Fatal("raw CSP resolved lifecycle intent", err)
	}
	if err = f.store.CancelUnenrollmentRequest(ctx, "admin", f.identity.Scope, f.identity.DeviceID, c.ID, c.Revision+1); !errors.Is(err, ErrCSPConflict) {
		t.Fatal("stale cancellation admitted", err)
	}
	if err = f.store.CancelUnenrollmentRequest(ctx, "admin", f.identity.Scope, f.identity.DeviceID, c.ID, c.Revision); err != nil {
		t.Fatal(err)
	}
	detail := unenrollmentRequestTestRead(t, f, c.ID)
	if detail.Command.Phase != "canceled" || detail.Reason != reason || detail.Release != nil {
		t.Fatal("cancellation lost protected intent")
	}
	unenrollmentRequestTestQueue(t, f)
	for _, table := range []string{"mdm_windows_unenrollment_requests", "mdm_windows_unenrollment_request_audit", "mdm_windows_csp_commands"} {
		var raw string
		if err = f.store.db.QueryRow(`SELECT json_agg(t)::text FROM ` + table + ` t`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(raw, reason) || strings.Contains(raw, "/DMClient/Unenroll") || strings.Contains(raw, f.options.ManagementURL) {
			t.Fatal("database plaintext exposed protected intent")
		}
	}
}

func TestWindowsUnenrollmentRequestDispatchReportAndNoImplicitCleanup(t *testing.T) {
	for _, status := range []string{"", "200", "202", "500"} {
		t.Run("status_"+status, func(t *testing.T) {
			f := syncMLTestStore(t)
			c := unenrollmentRequestTestQueue(t, f)
			normal := cspTestQueue(t, f, cspTestPolicy())
			request, delivery := cspTestStart(t, f)
			message := syncMLTestParsed(t, delivery)
			if len(message.Commands) != 2 || message.Commands[1].Kind != "Exec" || message.Commands[1].Items[0].Target.URI != "./Device/Vendor/MSFT/DMClient/Unenroll" || message.Commands[1].Items[0].Data.Text != f.options.ProviderID {
				t.Fatal("fixed disconnection was not prioritized")
			}
			if replay, err := f.process(request); err != nil || !bytes.Equal(replay, delivery) {
				t.Fatal("authorized exact delivery replay failed", err)
			}
			phase := "sent"
			if status != "" {
				reply := cspTestReply(message)
				reply.Commands[1].Data.Text = status
				response, err := f.process(syncMLTestWire(t, reply))
				if err != nil {
					t.Fatal(err)
				}
				if len(syncMLTestParsed(t, response).Commands) != 1 {
					t.Fatal("normal work followed a disconnection response")
				}
				phase = map[string]string{"200": "acknowledged", "202": "unknown", "500": "failed"}[status]
			}
			before := unenrollmentRequestTestRead(t, f, c.ID)
			if before.Command.Phase != phase || before.Release != nil || cspTestRead(t, f, normal.ID).Command.Phase != "queued" {
				t.Fatal("delivery/result confused with disconnection")
			}
			if identity, err := f.store.AuthenticateManagementDevice(managementTestRequest(t, f.certificate.Raw, f.options), f.options); err != nil || identity == nil {
				t.Fatal("Exec alone revoked access", err)
			}
			record, _ := f.state(t)
			reportRequest := syncMLTestWire(t, unenrollmentTestMessage(t, f, record.Nonces.ClientNonce))
			if _, err := f.process(reportRequest); err != nil {
				t.Fatal("authenticated disconnection notification rejected", err)
			}
			after := unenrollmentRequestTestRead(t, f, c.ID)
			if phase == "sent" {
				phase = "unknown"
			}
			if after.Command.Phase != phase {
				t.Fatal("notification invented an operation outcome", after.Command.Phase)
			}
			if report, err := f.store.UnenrollmentReport(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID); err != nil || report == nil {
				t.Fatal("separate report missing", err)
			}
			if bytes, err := f.process(request); !errors.Is(err, ErrManagementIdentity) || bytes != nil {
				t.Fatal("notification left delivery replay enabled", err)
			}
		})
	}
}

func TestWindowsUnenrollmentRequestReleasePreservesEvidence(t *testing.T) {
	for _, status := range []string{"", "200", "202", "500"} {
		t.Run("status_"+status, func(t *testing.T) {
			f := syncMLTestStore(t)
			c := unenrollmentRequestTestQueue(t, f)
			normal := cspTestQueue(t, f, cspTestPolicy())
			request, delivery := cspTestStart(t, f)
			if status != "" {
				reply := cspTestReply(syncMLTestParsed(t, delivery))
				reply.Commands[1].Data.Text = status
				if _, err := f.process(syncMLTestWire(t, reply)); err != nil {
					t.Fatal(err)
				}
			}
			before := unenrollmentRequestTestRead(t, f, c.ID)
			if err := f.store.ReleaseUnenrollmentRequest(t.Context(), "operator", f.identity.Scope, f.identity.DeviceID, c.ID, before.Command.Revision, "reviewed"); err == nil {
				t.Fatal("operator released disconnection")
			}
			if err := f.store.ReleaseUnenrollmentRequest(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, c.ID, before.Command.Revision+1, "reviewed"); !errors.Is(err, ErrCSPConflict) {
				t.Fatal("stale release admitted", err)
			}
			reason := "Investigated; device may still disconnect <script>review</script>"
			if err := f.store.ReleaseUnenrollmentRequest(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, c.ID, before.Command.Revision, reason); err != nil {
				t.Fatal(err)
			}
			after := unenrollmentRequestTestRead(t, f, c.ID)
			expected := before.Command.Phase
			if expected == "sent" {
				expected = "unknown"
			}
			if after.Release == nil || after.Release.Reason != reason || after.Release.ReviewedRevision != before.Command.Revision || after.Command.Phase != expected || after.Outcomes[0].Status != before.Outcomes[0].Status {
				t.Fatal("review rewrote evidence")
			}
			if err := f.store.ReleaseUnenrollmentRequest(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, c.ID, after.Command.Revision, reason); err == nil {
				t.Fatal("release silently repeated")
			}
			if data, err := f.process(request); err == nil || data != nil {
				t.Fatal("released payload replayed")
			}
			next := syncMLTestParsed(t, cspTestNextSession(t, f))
			if len(next.Commands) != 2 || cspTestRead(t, f, normal.ID).Command.Phase != "sent" {
				t.Fatal("review did not permit later authenticated management")
			}
			record, _ := f.state(t)
			if _, err := f.process(syncMLTestWire(t, unenrollmentTestMessage(t, f, record.Nonces.ClientNonce))); err != nil {
				t.Fatal("late notification failed after release", err)
			}
			if _, err := f.store.AuthenticateManagementDevice(managementTestRequest(t, f.certificate.Raw, f.options), f.options); !errors.Is(err, ErrManagementIdentity) {
				t.Fatal("release prevented late access retirement", err)
			}
		})
	}
}

func TestWindowsUnenrollmentRequestConcurrentIdentityAndMigration(t *testing.T) {
	f := syncMLTestStore(t)
	key := uuid.NewString()
	var wg sync.WaitGroup
	results := make(chan *CSPCommand, 6)
	errs := make(chan error, 6)
	for n := 0; n < 6; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := f.store.EnqueueUnenrollmentRequest(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, key, "Retire synthetic device", time.Hour, f.options)
			results <- c
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	id := ""
	for c := range results {
		if id != "" && c.ID != id {
			t.Fatal("retry race duplicated intent")
		}
		id = c.ID
	}
	unenrollmentTestCount(t, f.store, "mdm_windows_unenrollment_requests", 1)
	if err := f.store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	unenrollmentRequestTestRead(t, f, id)
}

func TestWindowsUnenrollmentRequestResultOwnerIsExact(t *testing.T) {
	payload, err := encodeUnenrollmentRequest(enrollmentTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	command, err := decodeUnenrollmentRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	state := newCSPSessionCommand(uuid.NewString(), "2", command)
	if state.validate() == nil {
		t.Fatal("custom result state admitted enrollment root")
	}
	state.UnenrollmentRequestID = state.CommandID
	if err = state.validate(); err != nil {
		t.Fatal("typed result state rejected", err)
	}
	state.UnenrollmentRequestID = uuid.NewString()
	if state.validate() == nil {
		t.Fatal("unrelated result owner admitted")
	}
	state.UnenrollmentRequestID = state.CommandID
	state.Operations[0].URI = "./Device/Vendor/MSFT/DMClient/Provider/Other/Unenroll"
	if state.validate() == nil {
		t.Fatal("typed result root was widened")
	}
}
