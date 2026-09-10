package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func testCSPExportSnapshots(t *testing.T, f syncMLStoreFixture, commandID string) {
	t.Helper()
	ctx := context.Background()
	command := cspTestRead(t, f, commandID).Command
	wholeSize := 0
	for _, message := range []int{0, 3, 4} {
		export, err := f.store.ExportCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, commandID, command.Revision, message)
		if err != nil {
			t.Fatal("export unavailable", err)
		}
		defer clear(export.Data)
		if message == 0 {
			wholeSize = len(export.Data)
		}
		var document struct {
			Schema   string `json:"schema"`
			Version  int    `json:"schema_version"`
			AuditID  int64  `json:"audit_id"`
			Complete bool   `json:"history_complete"`
			Count    int    `json:"observation_count"`
			Command  struct {
				ID       string `json:"id"`
				Revision int64  `json:"revision"`
				Phase    string `json:"phase"`
			} `json:"command"`
			CurrentResult struct {
				Operations []struct {
					Data struct {
						Value string `json:"value"`
					} `json:"data"`
				} `json:"operations"`
			} `json:"current_result"`
			Observations []struct {
				Message    int    `json:"message_id"`
				Outcome    string `json:"outcome"`
				Operations []struct {
					Incomplete bool `json:"incomplete"`
					Data       *struct {
						Representation string `json:"representation"`
						Value          string `json:"value"`
					} `json:"data"`
				} `json:"operations"`
			} `json:"observations"`
		}
		if err := json.Unmarshal(export.Data, &document); err != nil {
			t.Fatal("invalid JSON", err)
		}
		if document.Schema != "openuem.windows.csp-evidence" || document.Version != 1 || document.AuditID < 1 || document.Complete != (message == 0) || document.Command.ID != commandID || document.Command.Revision != command.Revision || document.Command.Phase != "acknowledged" || document.Count != len(document.Observations) || document.CurrentResult.Operations[0].Data.Value != "abcd" {
			t.Fatal("export lost identity or current result")
		}
		wantCount := 1
		if message == 0 {
			wantCount = 2
		}
		if document.Count != wantCount {
			t.Fatal("export lost observation selection")
		}
		for _, observation := range document.Observations {
			if message != 0 && observation.Message != message {
				t.Fatal("selected export included another message")
			}
			if len(observation.Operations) != 1 {
				t.Fatal("operation missing")
			}
			op := observation.Operations[0]
			if observation.Message == 3 {
				if observation.Outcome != "" || !op.Incomplete || op.Data != nil {
					t.Fatal("partial snapshot acquired later evidence")
				}
			} else if observation.Message != 4 || observation.Outcome != "acknowledged" || op.Incomplete || op.Data == nil || op.Data.Representation != "text" || op.Data.Value != "abcd" {
				t.Fatal("completed value changed")
			}
		}
		var action, actor string
		if err := f.store.db.QueryRow(`SELECT action,actor FROM mdm_windows_csp_audit WHERE id=$1 AND command_id=$2`, document.AuditID, commandID).Scan(&action, &actor); err != nil {
			t.Fatal(err)
		}
		wantAction := "command.exported"
		if message != 0 {
			wantAction = "command.observation_exported"
		}
		if action != wantAction || actor != "admin" {
			t.Fatal("export audit lost actor or kind")
		}
		data, err := json.Marshal(export)
		if err != nil || string(data) != "{}" || strings.Contains(fmt.Sprintf("%v %+v %#v", export, export, export), "abcd") {
			t.Fatal("ordinary export formatting leaked")
		}
		for _, secret := range []string{"encrypted_", "request_digest", "NextNonce", "ClientSecret", "ServerSecret", "Salt"} {
			if bytes.Contains(export.Data, []byte(secret)) {
				t.Fatal("transport internals escaped")
			}
		}
	}
	for _, actor := range []string{"operator", "viewer", "foreign", "missing"} {
		if value, err := f.store.ExportCSPCommand(ctx, actor, f.identity.Scope, f.identity.DeviceID, commandID, command.Revision, 0); err == nil || value != nil {
			t.Fatal("unauthorized export escaped", actor)
		}
	}
	if value, err := f.store.ExportCSPCommand(ctx, "admin", access.Scope{TenantID: 1, SiteID: 12}, f.identity.DeviceID, commandID, command.Revision, 0); !errors.Is(err, ErrNotFound) || value != nil {
		t.Fatal("foreign site exported")
	}
	for _, invalid := range []struct {
		id       string
		revision int64
		message  int
		want     error
	}{
		{commandID, command.Revision - 1, 0, ErrCSPConflict}, {commandID, 0, 0, ErrCSPCommand}, {commandID, command.Revision, -1, ErrCSPCommand}, {commandID, command.Revision, 65, ErrCSPCommand}, {commandID, command.Revision, 5, ErrNotFound}, {"bad", 1, 0, ErrCSPCommand}, {uuid.NewString(), 1, 0, ErrNotFound},
	} {
		if value, err := f.store.ExportCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, invalid.id, invalid.revision, invalid.message); !errors.Is(err, invalid.want) || value != nil {
			t.Fatal("invalid export admitted", err)
		}
	}
	var before, after int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM mdm_windows_csp_audit WHERE action LIKE '%exported'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, byteLimit := range []int{1, wholeSize - 1} {
		if value, err := f.store.exportCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, commandID, command.Revision, 0, byteLimit); !errors.Is(err, ErrCSPExportTooLarge) || value != nil {
			t.Fatal("oversize export escaped", err)
		}
	}
	if err := f.store.db.QueryRow(`SELECT count(*) FROM mdm_windows_csp_audit WHERE action LIKE '%exported'`).Scan(&after); err != nil || after != before {
		t.Fatal("failed export committed its audit", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if value, err := f.store.ExportCSPCommand(canceled, "admin", f.identity.Scope, f.identity.DeviceID, commandID, command.Revision, 0); !errors.Is(err, context.Canceled) || value != nil {
		t.Fatal("canceled export escaped", err)
	}
	hold, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	if _, err := hold.Exec(`SELECT pg_advisory_xact_lock(684627957)`); err != nil {
		t.Fatal(err)
	}
	if value, err := f.store.ExportCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, commandID, command.Revision, 0); !errors.Is(err, ErrCSPExportBusy) || value != nil {
		t.Fatal("concurrent export limit ignored", err)
	}
}

func TestCSPExportEncodingPreservesValuesAndBounds(t *testing.T) {
	intent := cspExportRequest(SyncMLCommand{ID: "1", Kind: "Sequence", Commands: []SyncMLCommand{{ID: "2", Kind: "Replace", Items: []SyncMLItem{{Target: &SyncMLLocation{URI: "./Device/Vendor/MSFT/Test/Value"}, Meta: &SyncMLMeta{Format: "chr", Type: "text/plain", NextNonce: "must-not-export"}, Data: &SyncMLData{Text: "  <script>α & β</script>\n"}}}}}})
	data, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	var decoded cspExportIntent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Children) != 1 || decoded.Children[0].Data.Value != "  <script>α & β</script>\n" || decoded.Children[0].ID != "2" || bytes.Contains(data, []byte("<script>")) || bytes.Contains(data, []byte("must-not-export")) {
		t.Fatal("intent or encoding boundary changed")
	}
	outcomes := cspExportOutcomes([]CSPOperationOutcome{{Incomplete: true, Data: &SyncMLData{Text: "partial-secret"}}, {Data: &SyncMLData{}}, {Status: 200, Data: &SyncMLData{XML: `<x xmlns="urn:synthetic">&amp;</x>`}}})
	if outcomes[0].Data != nil || outcomes[0].Status != nil || outcomes[1].Data == nil || outcomes[1].Data.Value != "" || outcomes[2].Data.Representation != "xml" || *outcomes[2].Status != 200 {
		t.Fatal("partial, absent or empty data collapsed")
	}
	for _, value := range []any{intent, decoded, outcomes[2]} {
		if strings.Contains(fmt.Sprintf("%v %+v %#v", value, value, value), "urn:synthetic") || strings.Contains(fmt.Sprintf("%v %+v %#v", value, value, value), "script") {
			t.Fatal("private DTO diagnostics leaked")
		}
	}
	b := &cspExportBuffer{ctx: context.Background(), limit: 4}
	if n, err := b.Write([]byte("abcd")); err != nil || n != 4 {
		t.Fatal("exact byte limit rejected")
	}
	if n, err := b.Write([]byte("e")); !errors.Is(err, ErrCSPExportTooLarge) || n != 0 || string(b.data) != "abcd" {
		t.Fatal("oversize write emitted partial bytes")
	}
}

func TestCSPExportMigrationAndRevokedHistory(t *testing.T) {
	f := syncMLTestStore(t)
	queued := cspTestQueue(t, f, cspTestPolicy())
	initial, delivery := cspTestStart(t, f)
	// Restore only the pre-export audit constraint in the owned fixture schema.
	if _, err := f.store.db.Exec(`DELETE FROM mdm_windows_migrations WHERE name='migrations/016_csp_exports.sql'; ALTER TABLE mdm_windows_csp_audit DROP CONSTRAINT mdm_windows_csp_audit_action_check; ALTER TABLE mdm_windows_csp_audit ADD CONSTRAINT mdm_windows_csp_audit_action_check CHECK(action NOT IN ('command.exported','command.observation_exported'))`); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		if err := f.store.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if replay, err := f.process(initial); err != nil || !bytes.Equal(replay, delivery) {
		t.Fatal("export migration changed enrollment or session replay", err)
	}
	if _, err := f.process(syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, delivery)))); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeDevice(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID); err != nil {
		t.Fatal(err)
	}
	command := cspTestRead(t, f, queued.ID).Command
	if result, err := f.store.ExportCSPCommand(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, queued.ID, command.Revision, 0); err != nil || result == nil {
		t.Fatal("retirement erased exportable history", err)
	} else {
		clear(result.Data)
	}
}

func TestCSPExportRechecksPermissionAfterLockWait(t *testing.T) {
	f := syncMLTestStore(t)
	queued := cspTestQueue(t, f, cspTestPolicy())
	if err := f.store.permissions.ReplaceGrants(t.Context(), "admin", "second", 1, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	hold, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	var pid int
	if err := hold.QueryRow(`SELECT pg_backend_pid(),pg_advisory_xact_lock(684627902)`).Scan(&pid, new(any)); err != nil {
		t.Fatal(err)
	}
	if _, err := hold.Exec(`DELETE FROM uem_access_grants WHERE user_id='second'`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		result, err := f.store.ExportCSPCommand(ctx, "second", f.identity.Scope, f.identity.DeviceID, queued.ID, queued.Revision, 0)
		if result != nil {
			clear(result.Data)
			err = errors.New("unauthorized export returned")
		}
		done <- err
	}()
	waitForCredentialLock(t, f.store.db, pid, 1)
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, access.ErrDenied) {
		t.Fatal("export retained stale grants", err)
	}
}

func TestCSPExportRejectsMissingLifecycleProof(t *testing.T) {
	for _, phase := range []string{"queued", "blocked", "canceled"} {
		t.Run(phase, func(t *testing.T) {
			f := syncMLTestStore(t)
			command := cspTestQueue(t, f, cspTestPolicy())
			// Authorized initial intent has no result yet and remains exportable.
			result, err := f.store.ExportCSPCommand(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, command.ID, 1, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(result.Data, []byte(`"observations":[]`)) || !bytes.Contains(result.Data, []byte(`"observation_count":0`)) {
				t.Fatal("undelivered export invented evidence")
			}
			clear(result.Data)
			if _, err := f.store.db.Exec(`UPDATE mdm_windows_csp_commands SET revision=revision+1,phase=$2,completed_at=CASE WHEN $2='canceled' THEN updated_at ELSE NULL END WHERE id=$1`, command.ID, phase); err != nil {
				t.Fatal(err)
			}
			if result, err := f.store.ExportCSPCommand(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, command.ID, 2, 0); !errors.Is(err, ErrAuthoritySecret) || result != nil {
				t.Fatal("changed metadata without lifecycle proof exported", err)
			}
			if result, err := f.store.CSPCommandDetails(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, command.ID); !errors.Is(err, ErrAuthoritySecret) || result != nil {
				t.Fatal("ordinary detail trusted missing lifecycle proof", err)
			}
			// Neither an export nor subsequent dispatch may legitimize the
			// altered undelivered row by replacing its missing proof.
			first, err := f.process(f.initial(t))
			if err != nil {
				t.Fatal(err)
			}
			if phase != "canceled" {
				if data, err := f.process(syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))); !errors.Is(err, ErrAuthoritySecret) || data != nil {
					t.Fatal("corrupt lifecycle metadata reached dispatch", err)
				}
			}
		})
	}
}

func TestCSPExportRevisionRefreshesAfterCommandLockWait(t *testing.T) {
	f := syncMLTestStore(t)
	queued := cspTestQueue(t, f, cspTestPolicy())
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
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
	command, err := scanCSPCommand(hold.QueryRow(`SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE id=$1 FOR UPDATE`, queued.ID))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		result, err := f.store.ExportCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, queued.ID, 1, 0)
		if result != nil {
			clear(result.Data)
			err = errors.New("stale export returned")
		}
		done <- err
	}()
	waitForCredentialLock(t, f.store.db, pid, 1)
	if err := f.store.blockCSP(ctx, hold, command, "synthetic_size_limit"); err != nil {
		t.Fatal(err)
	}
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrCSPConflict) {
		t.Fatal("export used revision from before lock wait", err)
	}
}
