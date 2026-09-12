package windows

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func updateTestQueue(t *testing.T, f syncMLStoreFixture, policy UpdatePolicy, remove bool) *UpdateRun {
	t.Helper()
	run, err := f.store.EnqueueUpdatePolicy(context.Background(), "operator", f.identity.Scope, f.identity.DeviceID, uuid.NewString(), "Synthetic update ring", policy, remove, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func updateTestRead(t *testing.T, f syncMLStoreFixture, id string) *UpdateRunDetail {
	t.Helper()
	detail, err := f.store.UpdateRunDetails(context.Background(), "operator", f.identity.Scope, f.identity.DeviceID, id)
	if err != nil {
		t.Fatal(err)
	}
	return detail
}

func updateTestReply(response *SyncMLMessage, policy UpdatePolicy, remove, drift bool) *SyncMLMessage {
	request := cspTestReply(response)
	settings, _ := policy.settings()
	for n := range request.Commands {
		c := &request.Commands[n]
		if c.Kind != "Results" {
			continue
		}
		item := &c.Items[0]
		switch item.Source.URI {
		case updateVersionURI:
			item.Data.Text = "10.0.26100.1"
		case updateEditionURI:
			item.Data.Text = "4"
			item.Meta.Format = "int"
		case updateProductURI:
			item.Data.Text = "Windows 11 Enterprise"
		case updateArchitectureURI:
			item.Data.Text = "9"
		default:
			for _, setting := range settings {
				if item.Source.URI == updateConfigRoot+setting.Name || item.Source.URI == updateResultRoot+setting.Name {
					value := setting.Value
					if drift && strings.HasPrefix(item.Source.URI, updateResultRoot) {
						value++
					}
					item.Meta.Format = "int"
					item.Data.Text = strconv.Itoa(value)
				}
			}
		}
	}
	if remove {
		absent := map[string]bool{}
		filtered := request.Commands[:0]
		for _, c := range request.Commands {
			if c.Kind == "Results" && strings.HasPrefix(c.Items[0].Source.URI, updateConfigRoot) {
				absent[c.CommandRef] = true
				continue
			}
			filtered = append(filtered, c)
		}
		request.Commands = filtered
		for n := range request.Commands {
			c := &request.Commands[n]
			if c.Kind == "Status" && absent[c.CommandRef] {
				c.Data.Text = "404"
			}
		}
	}
	return request
}

func TestUpdateRunOperatorDispatchReadbackRestartAndRemoval(t *testing.T) {
	for _, mode := range []string{"apply", "drift", "remove", "failed", "absent"} {
		t.Run(mode, func(t *testing.T) {
			f := syncMLTestStore(t)
			policy := updateTestFullPolicy()
			run := updateTestQueue(t, f, policy, mode == "remove")
			_, response := cspTestStart(t, f)
			detail := updateTestRead(t, f, run.ID)
			if detail.Phase != "preflight_pending" || detail.Steps[0].Phase != "sent" || detail.Steps[1].Phase != "queued" {
				t.Fatal("mutation preceded platform evidence")
			}
			for step := 0; step < len(detail.Steps); step++ {
				if len(response) > 5000 {
					t.Fatal("typed stage exceeded the default response limit", step, len(response))
				}
				reply := updateTestReply(syncMLTestParsed(t, response), policy, mode == "remove", mode == "drift")
				if step == 2 && (mode == "failed" || mode == "absent") {
					status := "500"
					if mode == "absent" {
						status = "404"
					}
					updateTestReadError(reply, updateConfigRoot+"DeferQualityUpdatesPeriodInDays", status)
				}
				request := syncMLTestWire(t, reply)
				var err error
				response, err = f.process(request)
				if err != nil {
					t.Fatal("typed update exchange failed", step, err)
				}
				detail = updateTestRead(t, f, run.ID)
				if step == 0 && (detail.Phase != "configuration_pending" || !detail.Platform.Compatible) {
					t.Fatal("preflight did not unlock validated configuration", detail.Phase, detail.Reason)
				}
				if step >= 1 && step < len(detail.Steps)-1 && detail.Phase != "verification_pending" {
					t.Fatal("acknowledgment was confused with read-back", detail.Phase)
				}
				if step >= 2 && len(detail.Outcomes) != min((step-1)*3, 13) {
					t.Fatal("completed batch evidence was lost while later reads progressed", step, len(detail.Outcomes))
				}
				if replay, err := f.process(request); err != nil || !bytes.Equal(replay, response) {
					t.Fatal("update step replay changed bytes", err)
				}
				f.store, err = NewStoreWithMasterKey(f.store.db, authorityTestMasterKey)
				if err != nil {
					t.Fatal(err)
				}
			}
			detail = updateTestRead(t, f, run.ID)
			want := map[string]string{"apply": "verified", "drift": "drifted", "remove": "removed", "failed": "verification_failed", "absent": "drifted"}[mode]
			if detail.Phase != want || len(detail.Outcomes) != 13 {
				t.Fatal("typed result did not preserve effective state", detail.Phase)
			}
			if _, err := f.store.CSPCommandDetails(context.Background(), "operator", f.identity.Scope, f.identity.DeviceID, detail.Steps[0].ID); !errors.Is(err, access.ErrDenied) {
				t.Fatal("typed operator obtained arbitrary CSP access", err)
			}
		})
	}
}

func TestUpdateRunRejectsIncompatiblePlatformWithoutMutation(t *testing.T) {
	f := syncMLTestStore(t)
	policy := updateTestPolicy()
	run := updateTestQueue(t, f, policy, false)
	_, response := cspTestStart(t, f)
	request := updateTestReply(syncMLTestParsed(t, response), policy, false, false)
	for n := range request.Commands {
		c := &request.Commands[n]
		if c.Kind == "Results" && c.Items[0].Source.URI == updateVersionURI {
			c.Items[0].Data.Text = "10.0.17763.1"
		}
	}
	final, err := f.process(syncMLTestWire(t, request))
	if err != nil {
		t.Fatal(err)
	}
	detail := updateTestRead(t, f, run.ID)
	if detail.Phase != "unsupported" || detail.Steps[1].Phase != "canceled" || detail.Steps[2].Phase != "canceled" || len(syncMLTestParsed(t, final).Commands) != 1 {
		t.Fatal("unsupported device received policy mutation", detail.Phase)
	}
}

func TestUpdateRunScopeIdempotencyCancellationAndAtomicAudit(t *testing.T) {
	f := syncMLTestStore(t)
	ctx := context.Background()
	key := uuid.NewString()
	policy := updateTestPolicy()
	for _, actor := range []string{"viewer", "foreign", "missing"} {
		if run, err := f.store.EnqueueUpdatePolicy(ctx, actor, f.identity.Scope, f.identity.DeviceID, key, "Synthetic ring", policy, false, time.Hour); err == nil || run != nil {
			t.Fatal("unprivileged update intent accepted")
		}
	}
	run, err := f.store.EnqueueUpdatePolicy(ctx, "operator", f.identity.Scope, f.identity.DeviceID, key, "Synthetic ring", policy, false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.store.EnqueueUpdatePolicy(ctx, "operator", f.identity.Scope, f.identity.DeviceID, key, "Synthetic ring", policy, false, time.Hour)
	if err != nil || replay.ID != run.ID {
		t.Fatal("update retry created new work", err)
	}
	if _, err := f.store.EnqueueUpdatePolicy(ctx, "operator", f.identity.Scope, f.identity.DeviceID, key, "Changed ring", policy, false, time.Hour); !errors.Is(err, ErrCSPConflict) {
		t.Fatal("conflicting update intent accepted", err)
	}
	if _, err := f.store.UpdateRunDetails(ctx, "operator", access.Scope{TenantID: 1, SiteID: 12}, f.identity.DeviceID, run.ID); err == nil {
		t.Fatal("typed update read crossed site")
	}
	if _, err := f.store.db.Exec(`CREATE FUNCTION reject_update_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic update audit failure'; END; $$; CREATE TRIGGER reject_update_audit BEFORE INSERT ON mdm_windows_update_audit FOR EACH ROW EXECUTE FUNCTION reject_update_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CancelUpdateRun(ctx, "operator", f.identity.Scope, f.identity.DeviceID, run.ID); err == nil {
		t.Fatal("unaudited cancellation succeeded")
	}
	if value, err := f.store.UpdateRunDetails(ctx, "operator", f.identity.Scope, f.identity.DeviceID, run.ID); err == nil || value != nil {
		t.Fatal("unaudited update payload read succeeded")
	}
	if value, err := f.store.EnqueueUpdatePolicy(ctx, "operator", f.identity.Scope, f.identity.DeviceID, uuid.NewString(), "Synthetic ring", policy, false, time.Hour); err == nil || value != nil {
		t.Fatal("unaudited update intent succeeded")
	}
	if _, err := f.store.db.Exec(`DROP TRIGGER reject_update_audit ON mdm_windows_update_audit`); err != nil {
		t.Fatal(err)
	}
	detail := updateTestRead(t, f, run.ID)
	if detail.Steps[0].Phase != "queued" {
		t.Fatal("audit rollback left partial cancellation")
	}
	var runs, commands int
	if err := f.store.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_windows_update_runs),(SELECT count(*) FROM mdm_windows_csp_commands)`).Scan(&runs, &commands); err != nil || runs != 1 || commands != len(detail.Steps) {
		t.Fatal("audit rollback left orphan update steps", err)
	}
	if err := f.store.CancelUpdateRun(ctx, "operator", f.identity.Scope, f.identity.DeviceID, run.ID); err != nil {
		t.Fatal(err)
	}
	if updateTestRead(t, f, run.ID).Phase != "canceled" {
		t.Fatal("update cancellation did not persist")
	}
	list, err := f.store.UpdateRuns(ctx, "operator", f.identity.Scope, f.identity.DeviceID, 0, 100)
	if err != nil || len(list) != 1 || list[0].Run.ID != run.ID || list[0].Phase != "canceled" {
		t.Fatal("scoped update listing lost its verified state", err)
	}
	if list, err := f.store.UpdateRuns(ctx, "viewer", f.identity.Scope, f.identity.DeviceID, 0, 100); !errors.Is(err, access.ErrDenied) || list != nil {
		t.Fatal("viewer read protected update intent", err)
	}
}
