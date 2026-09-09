package windows

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

func cspTestNextSession(t *testing.T, f syncMLStoreFixture) []byte {
	t.Helper()
	record, _ := f.state(t)
	secrets := *f.secrets
	secrets.ClientNonce = record.Nonces.ClientNonce
	initial := syncMLTestInitial(f.identity, f.options, &secrets)
	initial.Header.SessionID = "2"
	first, err := f.process(syncMLTestWire(t, initial))
	if err != nil {
		t.Fatal("new authenticated session rejected", err)
	}
	response, err := f.process(syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first))))
	if err != nil {
		t.Fatal("new session probe rejected", err)
	}
	return response
}

func TestCSPDurableChunksRestartAndInterruptedObjects(t *testing.T) {
	for _, end := range []string{"complete", "size mismatch", "interrupted"} {
		t.Run(end, func(t *testing.T) {
			f := syncMLTestStore(t)
			queued := cspTestQueue(t, f, CSPCommandSpec{Kind: "Get", URI: "./DevDetail/SwV"})
			_, delivery := cspTestStart(t, f)
			first := cspTestReply(syncMLTestParsed(t, delivery))
			first.Final = false
			size := uint64(4)
			first.Commands[2].Items[0].Meta.Size = &size
			first.Commands[2].Items[0].Data.Text = "ab"
			first.Commands[2].Items[0].MoreData = true
			request := syncMLTestWire(t, first)
			response, err := f.process(request)
			if err != nil {
				t.Fatal("first CSP result chunk rejected", err)
			}
			detail := cspTestRead(t, f, queued.ID)
			if detail.Command.Phase != "sent" || !detail.Outcomes[0].Incomplete || detail.Outcomes[0].Data != nil {
				t.Fatal("partial data was exposed as a complete result")
			}
			f.store, err = NewStoreWithMasterKey(f.store.db, authorityTestMasterKey)
			if err != nil {
				t.Fatal(err)
			}
			if replay, err := f.process(request); err != nil || !bytes.Equal(replay, response) {
				t.Fatal("restart duplicated or lost partial result", err)
			}
			last := cspTestReply(syncMLTestParsed(t, response))
			if end != "interrupted" {
				part := first.Commands[2]
				part.ID = strconv.Itoa(len(last.Commands) + 1)
				part.Items = []SyncMLItem{{Source: part.Items[0].Source, Data: &SyncMLData{Text: "cd"}}}
				if end == "size mismatch" {
					part.Items[0].Data.Text = "c"
				}
				last.Commands = append(last.Commands, part)
			}
			final, err := f.process(syncMLTestWire(t, last))
			if err != nil {
				t.Fatal("CSP result continuation rejected", err)
			}
			detail = cspTestRead(t, f, queued.ID)
			if end == "complete" {
				if detail.Command.Phase != "acknowledged" || detail.Outcomes[0].Data == nil || detail.Outcomes[0].Data.Text != "abcd" {
					t.Fatal("durable chunks did not reconstruct the original object")
				}
			} else {
				if detail.Command.Phase != "unknown" || detail.Outcomes[0].Data != nil {
					t.Fatal("incomplete CSP result claimed completion")
				}
				want := "424"
				if end == "interrupted" {
					want = "1225"
				}
				found := false
				for _, c := range syncMLTestParsed(t, final).Commands {
					found = found || c.Data != nil && c.Data.Text == want
				}
				if !found {
					t.Fatal("missing bounded-object protocol failure", want)
				}
			}
		})
	}
}

func TestCSPDeferredUserAndSizeLimits(t *testing.T) {
	for _, reason := range []string{"user_context", "message_size", "object_size"} {
		t.Run(reason, func(t *testing.T) {
			f := syncMLTestStore(t)
			spec := cspTestPolicy()
			spec.Format, spec.Data = "chr", &SyncMLData{Text: strings.Repeat("x", 3000)}
			if reason == "user_context" {
				spec.URI = "./User/Vendor/MSFT/WiFi/Profile/Synthetic/WlanXml"
			}
			queued := cspTestQueue(t, f, spec)
			initial := syncMLTestInitial(f.identity, f.options, f.secrets)
			if reason == "user_context" {
				initial.Commands[0].Items[0].Data.Text = "others"
			}
			first, err := f.process(syncMLTestWire(t, initial))
			if err != nil {
				t.Fatal(err)
			}
			request := syncMLTestReply(syncMLTestParsed(t, first))
			limit := uint64(2000)
			if reason == "message_size" {
				request.Header.Meta = &SyncMLMeta{MaxMessageSize: &limit}
			} else if reason == "object_size" {
				request.Header.Meta = &SyncMLMeta{MaxObjectSize: &limit}
			}
			response, err := f.process(syncMLTestWire(t, request))
			if err != nil || len(syncMLTestParsed(t, response).Commands) != 1 {
				t.Fatal("ineligible command reached the device", err)
			}
			detail := cspTestRead(t, f, queued.ID)
			if detail.Command.Phase != "blocked" || detail.Reason != reason || detail.Command.DeliveredAt != nil {
				t.Fatal("queue did not retain a precise eligibility reason")
			}
			response = cspTestNextSession(t, f)
			if len(syncMLTestParsed(t, response).Commands) != 2 || cspTestRead(t, f, queued.ID).Command.Phase != "sent" {
				t.Fatal("eligible next session did not release the queued command")
			}
		})
	}
}

func TestCSPOutcomeBeforeFinalAndLateAsyncEvidence(t *testing.T) {
	for _, code := range []string{"200", "202", "500"} {
		t.Run(code, func(t *testing.T) {
			f := syncMLTestStore(t)
			queued := cspTestQueue(t, f, cspTestPolicy())
			_, delivery := cspTestStart(t, f)
			ack := cspTestReply(syncMLTestParsed(t, delivery))
			ack.Final = false
			ack.Commands[1].Data.Text = code
			response, err := f.process(syncMLTestWire(t, ack))
			if err != nil {
				t.Fatal(err)
			}
			before := cspTestRead(t, f, queued.ID)
			last := cspTestReply(syncMLTestParsed(t, response))
			if code == "202" {
				status := ack.Commands[1]
				status.ID = strconv.Itoa(len(last.Commands) + 1)
				status.Data = &SyncMLData{Text: "200"}
				last.Commands = append(last.Commands, status)
			}
			if _, err := f.process(syncMLTestWire(t, last)); err != nil {
				t.Fatal("finished command prevented session housekeeping", err)
			}
			after := cspTestRead(t, f, queued.ID)
			want := "acknowledged"
			if code == "500" {
				want = "failed"
			}
			if after.Command.Phase != want || code != "202" && after.Command.Revision != before.Command.Revision {
				t.Fatal("late package end changed the command outcome")
			}
		})
	}
}

func TestCSPUncertainOutcomeBlocksQueueUntilAuditedAbandonment(t *testing.T) {
	for _, end := range []string{"aborted", "expired", "202", "516"} {
		t.Run(end, func(t *testing.T) {
			f := syncMLTestStore(t)
			queued := cspTestQueue(t, f, cspTestPolicy())
			deliveryRequest, delivery := cspTestStart(t, f)
			next := cspTestQueue(t, f, cspTestPolicy())
			if end == "expired" {
				syncMLTestExpiry(t, f, time.Now().Add(-time.Millisecond))
				cspTestNextSession(t, f)
			} else {
				request := cspTestReply(syncMLTestParsed(t, delivery))
				if end == "aborted" {
					request.Commands = request.Commands[:1]
					request.Commands = append(request.Commands, SyncMLCommand{Kind: "Alert", ID: "2", Data: &SyncMLData{Text: "1223"}})
				} else {
					request.Commands[1].Data.Text = end
				}
				if _, err := f.process(syncMLTestWire(t, request)); err != nil {
					t.Fatal(err)
				}
				if data, err := f.process(deliveryRequest); !errors.Is(err, ErrCSPAlreadySent) || data != nil {
					t.Fatal("uncertain command was sent again", err)
				}
				cspTestNextSession(t, f)
			}
			detail := cspTestRead(t, f, queued.ID)
			if detail.Command.Phase != "unknown" || detail.Command.CompletedAt != nil || cspTestRead(t, f, next.ID).Command.Phase != "queued" {
				t.Fatal("uncertain effects did not stop further delivery")
			}
			ctx := context.Background()
			if err := f.store.AbandonCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, queued.ID, detail.Command.Revision+1, "Reviewed synthetic device evidence"); !errors.Is(err, ErrCSPConflict) {
				t.Fatal("stale abandonment revision accepted")
			}
			if err := f.store.AbandonCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, queued.ID, detail.Command.Revision, "Reviewed synthetic device evidence"); err != nil {
				t.Fatal(err)
			}
			detail = cspTestRead(t, f, queued.ID)
			if detail.Command.Phase != "abandoned" || detail.Resolution == "" || detail.Command.CompletedAt == nil {
				t.Fatal("explicit uncertainty resolution was not preserved")
			}
			response := cspTestNextSession(t, f)
			if len(syncMLTestParsed(t, response).Commands) != 2 || cspTestRead(t, f, next.ID).Command.Phase != "sent" {
				t.Fatal("resolved queue remained blocked")
			}
		})
	}
}
