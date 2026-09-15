package windows

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func cspTestQueue(t *testing.T, f syncMLStoreFixture, spec CSPCommandSpec) *CSPCommand {
	t.Helper()
	command, err := f.store.EnqueueCSPCommand(context.Background(), "admin", f.identity.Scope, f.identity.DeviceID, uuid.NewString(), spec, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func cspTestStart(t *testing.T, f syncMLStoreFixture) ([]byte, []byte) {
	t.Helper()
	first, err := f.process(f.initial(t))
	if err != nil {
		t.Fatal(err)
	}
	request := syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))
	response, err := f.process(request)
	if err != nil {
		t.Fatal("CSP dispatch failed", err)
	}
	return request, response
}

func cspTestReply(response *SyncMLMessage) *SyncMLMessage {
	n, _ := strconv.Atoi(response.Header.MessageID)
	request := &SyncMLMessage{Header: SyncMLHeader{SessionID: response.Header.SessionID, MessageID: strconv.Itoa(n + 1), Source: response.Header.Target, Target: response.Header.Source}, Final: true}
	syncMLStatus(request, response.Header.MessageID, "0", "SyncHdr", "212")
	var acknowledge func([]SyncMLCommand)
	acknowledge = func(commands []SyncMLCommand) {
		for _, command := range commands {
			if command.Kind == "Status" {
				continue
			}
			syncMLStatus(request, response.Header.MessageID, command.ID, command.Kind, "200")
			if command.Kind == "Get" {
				value := "42"
				if command.Items[0].Target.URI == "./DevInfo/DevId" {
					value = "synthetic-device-ä<&>"
				}
				request.Commands = append(request.Commands, SyncMLCommand{Kind: "Results", ID: strconv.Itoa(len(request.Commands) + 1), MessageRef: response.Header.MessageID, CommandRef: command.ID, Items: []SyncMLItem{{Source: &SyncMLLocation{URI: command.Items[0].Target.URI}, Meta: &SyncMLMeta{Format: "chr"}, Data: &SyncMLData{Text: value}}}})
			}
			acknowledge(command.Commands)
		}
	}
	acknowledge(response.Commands)
	return request
}

func cspTestRead(t *testing.T, f syncMLStoreFixture, id string) *CSPCommandDetail {
	t.Helper()
	detail, err := f.store.CSPCommandDetails(context.Background(), "admin", f.identity.Scope, f.identity.DeviceID, id)
	if err != nil {
		t.Fatal(err)
	}
	return detail
}

func TestCSPQueueDispatchGroupsResultsAndReplay(t *testing.T) {
	f := syncMLTestStore(t)
	spec := CSPCommandSpec{Kind: "Sequence", Commands: []CSPCommandSpec{{Kind: "Get", URI: "./DevDetail/SwV"}, {Kind: "Atomic", Commands: []CSPCommandSpec{cspTestPolicy()}}}}
	queued := cspTestQueue(t, f, spec)
	request, response := cspTestStart(t, f)
	message := syncMLTestParsed(t, response)
	if len(message.Commands) != 2 || message.Commands[1].Kind != "Sequence" {
		t.Fatal("queued CSP tree was not dispatched after authentication")
	}
	detail := cspTestRead(t, f, queued.ID)
	if detail.Command.Phase != "sent" || detail.Command.DeliveredMessage != 2 || len(detail.Outcomes) != 4 {
		t.Fatal("CSP delivery metadata or group structure missing")
	}
	var workers sync.WaitGroup
	failures := make(chan error, 8)
	for n := 0; n < 8; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			replay, err := f.process(request)
			if err == nil && !bytes.Equal(replay, response) {
				err = errors.New("CSP delivery replay changed bytes")
			}
			failures <- err
		}()
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	ack := syncMLTestWire(t, cspTestReply(message))
	final, err := f.process(ack)
	if err != nil {
		t.Fatal("correlated CSP result rejected", err)
	}
	if len(syncMLTestParsed(t, final).Commands) != 1 {
		t.Fatal("completed command emitted another operation")
	}
	detail = cspTestRead(t, f, queued.ID)
	if detail.Command.Phase != "acknowledged" || detail.Command.CompletedAt == nil || detail.Outcomes[1].Data == nil || detail.Outcomes[1].Data.Text != "42" {
		t.Fatal("CSP statuses and results did not complete atomically")
	}
	if data, err := f.process(request); !errors.Is(err, ErrCSPAlreadySent) || data != nil {
		t.Fatal("old delivery was replayed after observed completion", err)
	}
	if replay, err := f.process(ack); err != nil || !bytes.Equal(replay, final) {
		t.Fatal("completion receipt was not replayable", err)
	}
	var observations int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM mdm_windows_csp_observations WHERE command_id=$1`, queued.ID).Scan(&observations); err != nil || observations != 1 {
		t.Fatal("result replay duplicated observations", err)
	}
	if err := f.store.CancelCSPCommand(context.Background(), "admin", f.identity.Scope, f.identity.DeviceID, queued.ID, detail.Command.Revision); !errors.Is(err, ErrCSPAlreadySent) {
		t.Fatal("delivered command could be canceled")
	}
}

func TestCSPQueueAuthorizationIdempotencyAndPrivacy(t *testing.T) {
	f := syncMLTestStore(t)
	ctx := context.Background()
	key := uuid.NewString()
	spec := cspTestPolicy()
	for _, actor := range []string{"operator", "viewer", "foreign", "missing"} {
		if command, err := f.store.EnqueueCSPCommand(ctx, actor, f.identity.Scope, f.identity.DeviceID, key, spec, time.Hour); err == nil || command != nil {
			t.Fatal("unprivileged CSP enqueue succeeded")
		}
	}
	command, err := f.store.EnqueueCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, key, spec, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.store.EnqueueCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, key, spec, time.Hour)
	if err != nil || replay.ID != command.ID {
		t.Fatal("idempotent enqueue duplicated command", err)
	}
	changed := cspTestPolicy()
	changed.Data = &SyncMLData{Text: "8"}
	if _, err := f.store.EnqueueCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, key, changed, time.Hour); !errors.Is(err, ErrCSPConflict) {
		t.Fatal("request-key payload conflict accepted", err)
	}
	if _, err := f.store.CSPCommandDetails(ctx, "operator", f.identity.Scope, f.identity.DeviceID, command.ID); !errors.Is(err, access.ErrDenied) {
		t.Fatal("operator read raw CSP payload", err)
	}
	if _, err := f.store.CSPCommandDetails(ctx, "admin", access.Scope{TenantID: 1, SiteID: 12}, f.identity.DeviceID, command.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("CSP lookup crossed site", err)
	}
	other := cspTestQueue(t, f, spec)
	var a, b []byte
	if err := f.store.db.QueryRow(`SELECT request_digest FROM mdm_windows_csp_commands WHERE id=$1`, command.ID).Scan(&a); err != nil {
		t.Fatal(err)
	}
	if err := f.store.db.QueryRow(`SELECT request_digest FROM mdm_windows_csp_commands WHERE id=$1`, other.ID).Scan(&b); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("request digest exposed low-entropy equal CSP values")
	}
	for _, table := range []string{"mdm_windows_csp_commands", "mdm_windows_csp_audit"} {
		rows, err := f.store.db.Query(`SELECT row_to_json(t)::text FROM ` + table + ` t`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(value, cspTestPolicyURI) || strings.Contains(value, "<SyncML") {
				t.Fatal("CSP storage exposed plaintext request")
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
	if err := f.store.CancelCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, command.ID, command.Revision+1); !errors.Is(err, ErrCSPConflict) {
		t.Fatal("stale cancel revision accepted")
	}
	if err := f.store.CancelCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, command.ID, command.Revision); err != nil {
		t.Fatal(err)
	}
	list, err := f.store.CSPCommands(ctx, "admin", f.identity.Scope, f.identity.DeviceID, 0, 100)
	if err != nil || len(list) != 2 {
		t.Fatal("scoped CSP listing failed", err)
	}
}

func TestCSPResultReferenceAndAuditFailuresRollback(t *testing.T) {
	f := syncMLTestStore(t)
	command := cspTestQueue(t, f, CSPCommandSpec{Kind: "Get", URI: "./DevDetail/SwV"})
	_, response := cspTestStart(t, f)
	for name, mutate := range map[string]func(*SyncMLMessage){
		"wrong message":        func(m *SyncMLMessage) { m.Commands[1].MessageRef = "1" },
		"wrong command":        func(m *SyncMLMessage) { m.Commands[2].CommandRef = "foreign" },
		"wrong target":         func(m *SyncMLMessage) { m.Commands[2].Items[0].Source.URI = "./DevDetail/FwV" },
		"duplicate status":     func(m *SyncMLMessage) { c := m.Commands[1]; c.ID = "4"; m.Commands = append(m.Commands, c) },
		"duplicate result":     func(m *SyncMLMessage) { c := m.Commands[2]; c.ID = "4"; m.Commands = append(m.Commands, c) },
		"contradictory result": func(m *SyncMLMessage) { m.Commands[1].Data.Text = "500" },
	} {
		t.Run(name, func(t *testing.T) {
			m := cspTestReply(syncMLTestParsed(t, response))
			mutate(m)
			if data, err := f.process(syncMLTestWire(t, m)); err == nil || data != nil {
				t.Fatal("uncorrelated CSP result accepted")
			}
		})
	}
	if _, err := f.store.db.Exec(`CREATE FUNCTION reject_csp_observation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic CSP observation failure'; END; $$; CREATE TRIGGER reject_csp_observation BEFORE INSERT ON mdm_windows_csp_observations FOR EACH ROW EXECUTE FUNCTION reject_csp_observation()`); err != nil {
		t.Fatal(err)
	}
	valid := syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, response)))
	if data, err := f.process(valid); err == nil || data != nil {
		t.Fatal("failed observation persistence returned receipt")
	}
	detail := cspTestRead(t, f, command.ID)
	if detail.Command.Phase != "sent" || detail.Outcomes[0].Status != 0 {
		t.Fatal("rollback left a partial CSP result")
	}
	if _, err := f.store.db.Exec(`DROP TRIGGER reject_csp_observation ON mdm_windows_csp_observations`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.process(valid); err != nil {
		t.Fatal("retry after observation rollback failed", err)
	}
}

func TestCSPCreatorRevisionGuardsQueueAndReplayButAllowsEvidence(t *testing.T) {
	for _, sent := range []bool{false, true} {
		t.Run(fmt.Sprint("already sent ", sent), func(t *testing.T) {
			f := syncMLTestStore(t)
			ctx := context.Background()
			principal, err := f.store.permissions.Principal(ctx, "second")
			if err != nil {
				t.Fatal(err)
			}
			grants := []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}
			if err := f.store.permissions.ReplaceGrants(ctx, "admin", "second", principal.Revision, grants); err != nil {
				t.Fatal(err)
			}
			command, err := f.store.EnqueueCSPCommand(ctx, "second", f.identity.Scope, f.identity.DeviceID, uuid.NewString(), cspTestPolicy(), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			var request, response []byte
			if sent {
				request, response = cspTestStart(t, f)
			}
			principal, err = f.store.permissions.Principal(ctx, "second")
			if err != nil {
				t.Fatal(err)
			}
			// Even regranting identical rights is a new authority revision.
			if err := f.store.permissions.ReplaceGrants(ctx, "admin", "second", principal.Revision, grants); err != nil {
				t.Fatal(err)
			}
			if sent {
				if data, err := f.process(request); !errors.Is(err, access.ErrDenied) || data != nil {
					t.Fatal("stale creator authority released a stored CSP delivery", err)
				}
				if _, err := f.process(syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, response)))); err != nil {
					t.Fatal("authority loss discarded already-executed command evidence", err)
				}
				if cspTestRead(t, f, command.ID).Command.Phase != "acknowledged" {
					t.Fatal("late evidence was not recorded")
				}
			} else {
				_, response = cspTestStart(t, f)
				if len(syncMLTestParsed(t, response).Commands) != 1 || cspTestRead(t, f, command.ID).Command.Phase != "canceled" {
					t.Fatal("stale queued authority dispatched a CSP command")
				}
			}
		})
	}
}
