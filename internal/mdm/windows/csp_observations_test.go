package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestCSPObservationHistoryPreservesPartialAndCompletedSnapshots(t *testing.T) {
	f := syncMLTestStore(t)
	ctx := context.Background()
	queued := cspTestQueue(t, f, CSPCommandSpec{Kind: "Get", URI: "./DevDetail/SwV"})
	read := func(message int) *CSPObservationHistory {
		t.Helper()
		history, err := f.store.CSPObservationDetails(ctx, "admin", f.identity.Scope, f.identity.DeviceID, queued.ID, message)
		if err != nil || len(history.Observations) != 1 {
			t.Fatal("observation unavailable", err)
		}
		return history
	}
	list := func(offset, limit int) *CSPObservationHistory {
		t.Helper()
		history, err := f.store.CSPObservations(ctx, "admin", f.identity.Scope, f.identity.DeviceID, queued.ID, offset, limit)
		if err != nil {
			t.Fatal(err)
		}
		return history
	}
	if len(list(0, 11).Observations) != 0 {
		t.Fatal("queued command invented device evidence")
	}
	_, delivery := cspTestStart(t, f)
	first := cspTestReply(syncMLTestParsed(t, delivery))
	first.Final = false
	size := uint64(4)
	first.Commands[2].Items[0].Meta.Size = &size
	first.Commands[2].Items[0].Data.Text = "ab"
	first.Commands[2].Items[0].MoreData = true
	packet := syncMLTestWire(t, first)
	response, err := f.process(packet)
	if err != nil {
		t.Fatal(err)
	}
	partial := read(3).Observations[0]
	if partial.Outcome != "" || len(partial.Outcomes) != 1 || !partial.Outcomes[0].Incomplete || partial.Outcomes[0].Data != nil {
		t.Fatal("partial value exposed or called complete")
	}
	last := cspTestReply(syncMLTestParsed(t, response))
	part := first.Commands[2]
	part.ID = strconv.Itoa(len(last.Commands) + 1)
	part.Items = []SyncMLItem{{Source: part.Items[0].Source, Data: &SyncMLData{Text: "cd"}}}
	last.Commands = append(last.Commands, part)
	lastPacket := syncMLTestWire(t, last)
	if _, err := f.process(lastPacket); err != nil {
		t.Fatal(err)
	}
	f.store, err = NewStoreWithMasterKey(f.store.db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.process(lastPacket); err != nil {
		t.Fatal("replay after restart failed", err)
	}
	history := list(0, 11)
	if len(history.Observations) != 2 || history.Observations[0].MessageID != 3 || history.Observations[1].MessageID != 4 || history.Observations[1].ReceivedAt.Before(partial.ReceivedAt) {
		t.Fatal("chronology or replay uniqueness lost")
	}
	for _, observation := range history.Observations {
		if observation.Outcomes != nil {
			t.Fatal("list exposed operation values")
		}
	}
	if page := list(1, 1); len(page.Observations) != 1 || page.Observations[0].MessageID != 4 {
		t.Fatal("page lost stable message order")
	}
	if len(list(2, 1).Observations) != 0 {
		t.Fatal("page exceeded history")
	}
	complete := read(4).Observations[0]
	if complete.Outcome != "acknowledged" || complete.Outcomes[0].Data == nil || complete.Outcomes[0].Data.Text != "abcd" {
		t.Fatal("complete snapshot lost original object")
	}
	if before := read(3); before.Command.Phase != "acknowledged" || before.Observations[0].Outcome != "" || before.Observations[0].Outcomes[0].Data != nil {
		t.Fatal("current command rewrote earlier partial evidence")
	}
	testCSPExportSnapshots(t, f, queued.ID)
	for _, value := range []any{complete, *history} {
		data, err := json.Marshal(value)
		if err != nil || string(data) != "{}" || strings.Contains(fmt.Sprintf("%v %+v %#v", value, value, value), "abcd") {
			t.Fatal("protected history serialization leaked")
		}
	}
	for _, message := range []int{0, -1, 65} {
		if value, err := f.store.CSPObservationDetails(ctx, "admin", f.identity.Scope, f.identity.DeviceID, queued.ID, message); !errors.Is(err, ErrCSPCommand) || value != nil {
			t.Fatal("invalid message accepted")
		}
	}
	if value, err := f.store.CSPObservationDetails(ctx, "admin", f.identity.Scope, f.identity.DeviceID, queued.ID, 5); !errors.Is(err, ErrNotFound) || value != nil {
		t.Fatal("missing message invented")
	}
	for _, bounds := range [][2]int{{-1, 1}, {65, 1}, {0, 0}, {0, 12}} {
		if value, err := f.store.CSPObservations(ctx, "admin", f.identity.Scope, f.identity.DeviceID, queued.ID, bounds[0], bounds[1]); !errors.Is(err, ErrCSPCommand) || value != nil {
			t.Fatal("unbounded history accepted")
		}
	}
	for _, actor := range []string{"operator", "viewer", "foreign", "missing"} {
		if value, err := f.store.CSPObservations(ctx, actor, f.identity.Scope, f.identity.DeviceID, queued.ID, 0, 11); err == nil || value != nil {
			t.Fatal("unauthorized history escaped", actor)
		}
		if value, err := f.store.CSPObservationDetails(ctx, actor, f.identity.Scope, f.identity.DeviceID, queued.ID, 4); err == nil || value != nil {
			t.Fatal("unauthorized value escaped", actor)
		}
	}
	for _, commandID := range []string{"bad", uuid.NewString()} {
		if value, err := f.store.CSPObservations(ctx, "admin", f.identity.Scope, f.identity.DeviceID, commandID, 0, 11); err == nil || value != nil {
			t.Fatal("unrelated command history escaped")
		}
	}
	if value, err := f.store.CSPObservationDetails(ctx, "admin", access.Scope{TenantID: 1, SiteID: 12}, f.identity.DeviceID, queued.ID, 4); !errors.Is(err, ErrNotFound) || value != nil {
		t.Fatal("cross-site observation escaped")
	}
	if _, err := f.store.db.Exec(`CREATE FUNCTION fail_observation_read_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic observation audit failure'; END $$; CREATE TRIGGER fail_observation_read_audit BEFORE INSERT ON mdm_windows_csp_audit FOR EACH ROW EXECUTE FUNCTION fail_observation_read_audit()`); err != nil {
		t.Fatal(err)
	}
	if result, err := f.store.ExportCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, queued.ID, history.Command.Revision, 0); err == nil || result != nil {
		t.Fatal("unaudited export escaped")
	}
	for _, message := range []int{0, 4} {
		value, err := f.store.readCSPObservations(ctx, "admin", f.identity.Scope, f.identity.DeviceID, queued.ID, message, 0, 1)
		if err == nil || value != nil {
			t.Fatal("unaudited history escaped")
		}
	}
	if _, err := f.store.db.Exec(`DROP TRIGGER fail_observation_read_audit ON mdm_windows_csp_audit`); err != nil {
		t.Fatal(err)
	}
	cspTestObservationCorruption(t, f, queued.ID)
}

// Corruption is limited to the fixture's owned random schema. The original row
// is restored with its immutable-history trigger enabled after each case.
func cspTestObservationCorruption(t *testing.T, f syncMLStoreFixture, commandID string) {
	t.Helper()
	ctx := context.Background()
	c, err := scanCSPCommand(f.store.db.QueryRow(`SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE id=$1`, commandID))
	if err != nil {
		t.Fatal(err)
	}
	var digest, encrypted []byte
	var receivedAt time.Time
	if err := f.store.db.QueryRow(`SELECT request_digest,encrypted_observation,created_at FROM mdm_windows_csp_observations WHERE command_id=$1 AND message_id=4`, commandID).Scan(&digest, &encrypted, &receivedAt); err != nil {
		t.Fatal(err)
	}
	purpose := cspObservationPurpose(c, c.DeliveredSessionID, "4", digest, receivedAt)
	plain, err := f.store.secrets.openBounded(encrypted, purpose, maxCSPProtectedBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	change := func(ciphertext, digest []byte, stamp time.Time) {
		t.Helper()
		tx, err := f.store.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(`ALTER TABLE mdm_windows_csp_observations DISABLE TRIGGER mdm_windows_csp_observation_history`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`UPDATE mdm_windows_csp_observations SET encrypted_observation=$2,request_digest=$3,created_at=$4 WHERE command_id=$1 AND message_id=4`, commandID, ciphertext, digest, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`ALTER TABLE mdm_windows_csp_observations ENABLE TRIGGER mdm_windows_csp_observation_history`); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"ciphertext", "digest", "timestamp", "command", "message", "observed message", "operation URI", "wire ID", "wire index", "parent", "version"} {
		t.Run(name, func(t *testing.T) {
			ciphertext, boundDigest, stamp := append([]byte(nil), encrypted...), append([]byte(nil), digest...), receivedAt
			if name == "ciphertext" {
				ciphertext[len(ciphertext)-1] ^= 1
			} else if name == "digest" {
				boundDigest[0] ^= 1
			} else if name == "timestamp" {
				stamp = stamp.Add(time.Microsecond)
			} else {
				var state cspSessionCommand
				if err := decodeSyncMLProtectedJSON(plain, &state); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "command":
					state.CommandID = uuid.NewString()
				case "message":
					state.MessageID = "1"
				case "observed message":
					state.ObservedMessageID = "3"
				case "operation URI":
					state.Operations[0].URI = "./DevInfo/Man"
				case "wire ID":
					state.Operations[0].WireID = "different-wire"
				case "wire index":
					state.Operations[0].WireID = c.DeliveredSessionID + "-" + strconv.Itoa(c.DeliveredMessage) + "-9"
				case "parent":
					state.Operations[0].ParentID = "missing-parent"
				case "version":
					state.Version = 2
				}
				data, _ := json.Marshal(state)
				ciphertext, err = f.store.secrets.sealBounded(data, purpose, maxCSPProtectedBytes)
				clear(data)
				if err != nil {
					t.Fatal(err)
				}
			}
			change(ciphertext, boundDigest, stamp)
			defer change(encrypted, digest, receivedAt)
			for _, message := range []int{0, 4} {
				if result, err := f.store.ExportCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, commandID, c.Revision, message); err == nil || result != nil {
					t.Fatal("corrupted export escaped", name)
				}
				value, err := f.store.readCSPObservations(ctx, "admin", f.identity.Scope, f.identity.DeviceID, commandID, message, 0, 11)
				if err == nil || value != nil {
					t.Fatal("substituted snapshot escaped", name)
				}
			}
		})
	}
}
