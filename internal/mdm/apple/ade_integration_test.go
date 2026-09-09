package apple

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/ade"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/smallstep/pkcs7"
)

type adeFixtureService struct {
	account                 ade.Account
	accountError, pageError error
	page                    ade.Page
	fetch                   func(context.Context, string, bool) (ade.Page, error)
}

func (f *adeFixtureService) Account(context.Context) (ade.Account, error) {
	return f.account, f.accountError
}
func (f *adeFixtureService) Devices(ctx context.Context, cursor string, delta bool) (ade.Page, error) {
	if f.fetch != nil {
		return f.fetch(ctx, cursor, delta)
	}
	return f.page, f.pageError
}
func (*adeFixtureService) Close() {}

func adeFixture(t *testing.T) (*Store, string, *adeFixtureService) {
	t.Helper()
	s := testStore(t)
	f := &adeFixtureService{account: ade.Account{ServerID: uuid.NewString(), ServerName: "Synthetic Apple server", OrganizationID: "synthetic-organization", OrganizationName: "Example organization"}}
	s.adeService = func(*ade.Token) ade.Service { return f }
	id, err := s.createADEServer(t.Context(), 1, "Synthetic connection", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.importADEToken(t.Context(), 1, id, adeTokenEnvelope(t, s, 1, id, time.Now().Add(24*time.Hour)), "admin", nil); err != nil {
		t.Fatal(err)
	}
	return s, id, f
}
func adeTokenEnvelope(t *testing.T, s *Store, tenant int, id string, expiry time.Time) []byte {
	t.Helper()
	var der []byte
	if err := s.db.QueryRow(`SELECT certificate FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&der); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"consumer_key": "synthetic-consumer", "consumer_secret": "synthetic-consumer-secret", "access_token": "synthetic-access", "access_secret": "synthetic-access-secret", "access_token_expiry": expiry.UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	// This package's CMS encryption fixtures run sequentially; restore the library default.
	old := pkcs7.ContentEncryptionAlgorithm
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
	envelope, err := pkcs7.Encrypt(data, []*x509.Certificate{cert})
	pkcs7.ContentEncryptionAlgorithm = old
	clear(data)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
func adeExec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}
func adeDue(t *testing.T, s *Store, id string) {
	t.Helper()
	adeExec(t, s, `UPDATE mdm_apple_ade_servers SET next_sync_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id)
}
func adeState(t *testing.T, s *Store, id string) ADEServer {
	t.Helper()
	servers, err := s.ADEServers(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range servers {
		if server.ID == id {
			return server
		}
	}
	t.Fatal("connection missing")
	return ADEServer{}
}
func adePublished(t *testing.T, s *Store, id string) map[string]ADEDevice {
	t.Helper()
	list, _, err := s.ADEDevices(t.Context(), 1, id, "")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]ADEDevice{}
	for _, d := range list {
		out[d.Serial] = d
	}
	return out
}
func adeSync(t *testing.T, s *Store, id string) {
	t.Helper()
	adeDue(t, s, id)
	if err := s.syncADEServer(t.Context(), 1, id); err != nil {
		t.Fatal(err)
	}
}

func TestADETokenBindingEncryptionRenewalAndDisable(t *testing.T) {
	s, id, f := adeFixture(t)
	var sealed, key []byte
	var hash string
	var revision int64
	if err := s.db.QueryRow(`SELECT token,private_key,token_hash,token_revision FROM mdm_apple_ade_servers WHERE id=$1`, id).Scan(&sealed, &key, &hash, &revision); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("synthetic")) || bytes.Contains(key, []byte("PRIVATE KEY")) || revision != 1 {
		t.Fatal("credentials were not sealed")
	}
	if _, err := s.secrets.open(sealed, secretPurpose(2, id, "ade_token")); err == nil {
		t.Fatal("token escaped tenant binding")
	}
	oldAccount := f.account
	renewal := adeTokenEnvelope(t, s, 1, id, time.Now().Add(48*time.Hour))
	for _, mode := range []string{"wrong-server", "wrong-organization", "service-failure", "expired", "foreign-certificate", "audit-failure"} {
		t.Run(mode, func(t *testing.T) {
			f.account = oldAccount
			f.accountError = nil
			data := renewal
			switch mode {
			case "wrong-server":
				f.account.ServerID = uuid.NewString()
			case "wrong-organization":
				f.account.OrganizationID = "unrelated-organization"
			case "service-failure":
				f.accountError = ade.ErrService
			case "expired":
				data = adeTokenEnvelope(t, s, 1, id, time.Now().Add(-time.Hour))
			case "foreign-certificate":
				other, err := s.createADEServer(t.Context(), 2, "Other organization", "admin", nil)
				if err != nil {
					t.Fatal(err)
				}
				data = adeTokenEnvelope(t, s, 2, other, time.Now().Add(48*time.Hour))
			case "audit-failure":
				adeExec(t, s, `CREATE FUNCTION reject_ade_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.ade.token.import' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_ade_import BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_ade_import()`)
				defer adeExec(t, s, `DROP TRIGGER reject_ade_import ON mdm_apple_audit`)
			}
			if err := s.importADEToken(t.Context(), 1, id, data, "admin", nil); err == nil {
				t.Fatal("invalid renewal accepted")
			}
			var actual []byte
			var rev int64
			if err := s.db.QueryRow(`SELECT token,token_revision FROM mdm_apple_ade_servers WHERE id=$1`, id).Scan(&actual, &rev); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(actual, sealed) || rev != revision {
				t.Fatal("failed renewal replaced working credential")
			}
		})
	}
	f.account = oldAccount
	f.accountError = nil
	if err := s.importADEToken(t.Context(), 1, id, renewal, "admin", nil); err != nil {
		t.Fatal(err)
	}
	other, err := s.createADEServer(t.Context(), 2, "Duplicate server", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.importADEToken(t.Context(), 2, other, adeTokenEnvelope(t, s, 2, other, time.Now().Add(72*time.Hour)), "admin", nil); !errors.Is(err, ErrADEAccount) {
		t.Fatal("same Apple server attached to two tenants", err)
	}
	f.page = ade.Page{Devices: []ade.Device{{Serial: "SYNTHETIC1", Family: "Mac"}}, Cursor: "complete"}
	adeSync(t, s, id)
	if err = s.changeADEServer(t.Context(), 1, id, "disable", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if adeState(t, s, id).Status != "disabled" || len(adePublished(t, s, id)) != 1 {
		t.Fatal("disable lost history")
	}
	var isNull bool
	if err = s.db.QueryRow(`SELECT token IS NULL AND token_hash='' AND next_sync_at IS NULL FROM mdm_apple_ade_servers WHERE id=$1`, id).Scan(&isNull); err != nil || !isNull {
		t.Fatal("disable retained usable credentials", err)
	}
	if err = s.importADEToken(t.Context(), 1, id, renewal, "admin", nil); err != nil {
		t.Fatal("reconnect failed", err)
	}
	if adeState(t, s, id).Status != "connected" {
		t.Fatal("reconnect did not enable connection")
	}
	if _, _, err = s.ADEDevices(t.Context(), 2, id, ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant inventory readable")
	}
}

func TestADEFullFetchPublishesAtomicallyAndDeltaOrdersEvents(t *testing.T) {
	s, id, f := adeFixture(t)
	f.page = ade.Page{Devices: []ade.Device{{Serial: "OLD1", Model: "Retained history"}}, Cursor: "initial"}
	adeSync(t, s, id)
	if err := s.changeADEServer(t.Context(), 1, id, "reload", "admin", nil); err != nil {
		t.Fatal(err)
	}
	f.page = ade.Page{Devices: []ade.Device{{Serial: "NEW1", Model: "Page one"}}, Cursor: "page1", More: true}
	adeSync(t, s, id)
	if data := adePublished(t, s, id); len(data) != 1 || !data["OLD1"].Assigned {
		t.Fatal("partial fetch changed published snapshot")
	}
	f.pageError = ade.ErrService
	adeSync(t, s, id)
	f.pageError = nil
	if !adePublished(t, s, id)["OLD1"].Assigned {
		t.Fatal("failed continuation removed assignment")
	}
	f.fetch = func(_ context.Context, cursor string, delta bool) (ade.Page, error) {
		if cursor != "page1" || delta {
			t.Error("partial fetch lost its cursor")
		}
		return ade.Page{Devices: []ade.Device{{Serial: "NEW2", Model: "Page two"}}, Cursor: "complete"}, nil
	}
	adeSync(t, s, id)
	f.fetch = nil
	data := adePublished(t, s, id)
	if len(data) != 3 || data["OLD1"].Assigned || !data["NEW1"].Assigned || !data["NEW2"].Assigned || adeState(t, s, id).SyncMode != "delta" {
		t.Fatal("completed snapshot was not published atomically")
	}
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	f.page = ade.Page{Devices: []ade.Device{{Serial: "NEW1", Operation: "deleted", OperationAt: at.Add(time.Minute)}, {Serial: "NEW1", Model: "Older update", Operation: "modified", OperationAt: at}, {Serial: "NEW2", Model: "Current", Operation: "modified", OperationAt: at}}, Cursor: "delta1"}
	adeSync(t, s, id)
	data = adePublished(t, s, id)
	if data["NEW1"].Assigned || data["NEW1"].Model != "Page one" || data["NEW2"].Model != "Current" {
		t.Fatal("delta order or retained deletion metadata incorrect")
	}
	f.page = ade.Page{Devices: []ade.Device{{Serial: "NEW1", Model: "Late old event", Operation: "added", OperationAt: at}, {Serial: "NEW2", Model: "Current", Operation: "modified", OperationAt: at}}, Cursor: "delta2"}
	adeSync(t, s, id)
	if adePublished(t, s, id)["NEW1"].Assigned {
		t.Fatal("old event resurrected assignment")
	}
	f.page = ade.Page{Devices: []ade.Device{{Serial: "NEW2", Operation: "deleted", OperationAt: at}}, Cursor: "conflict"}
	adeSync(t, s, id)
	if state := adeState(t, s, id); state.SyncMode != "full" || state.SyncError != "cursor_reset" || !adePublished(t, s, id)["NEW2"].Assigned {
		t.Fatal("equal-date conflicting change invented a winner")
	}
	var native int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_devices`).Scan(&native); err != nil || native != 0 {
		t.Fatal("assignment fabricated native enrollment", err)
	}
}

func TestADECursorCyclesAuditRollbackBackoffAndAccountChange(t *testing.T) {
	s, id, f := adeFixture(t)
	f.page = ade.Page{Devices: []ade.Device{{Serial: "KEEP1"}}, Cursor: "initial"}
	adeSync(t, s, id)
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	f.page = ade.Page{Devices: []ade.Device{{Serial: "KEEP1", Operation: "deleted", OperationAt: at}}, Cursor: "next"}
	adeExec(t, s, `CREATE FUNCTION reject_ade_sync() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.ade.sync.page' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_ade_sync BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_ade_sync()`)
	adeDue(t, s, id)
	if err := s.syncADEServer(t.Context(), 1, id); err == nil {
		t.Fatal("audit failure committed a page")
	}
	var cursor string
	if err := s.db.QueryRow(`SELECT sync_cursor FROM mdm_apple_ade_servers WHERE id=$1`, id).Scan(&cursor); err != nil || cursor != "initial" || !adePublished(t, s, id)["KEEP1"].Assigned {
		t.Fatal("cursor or device escaped audit rollback", err)
	}
	adeExec(t, s, `DROP TRIGGER reject_ade_sync ON mdm_apple_audit`)
	f.pageError = &ade.RetryError{After: 48 * time.Hour}
	adeSync(t, s, id)
	f.pageError = nil
	state := adeState(t, s, id)
	if state.SyncError != "throttled" || state.RetryAfter == nil || state.RetryAfter.Before(time.Now().Add(47*time.Hour)) {
		t.Fatal("Apple backoff shortened")
	}
	for _, op := range []string{"sync", "reload"} {
		if err := s.changeADEServer(t.Context(), 1, id, op, "admin", nil); err != nil {
			t.Fatal(err)
		}
		if adeState(t, s, id).NextSyncAt.Before(*state.RetryAfter) {
			t.Fatal("manual action bypassed backoff")
		}
	}
	var calls atomic.Int32
	f.fetch = func(context.Context, string, bool) (ade.Page, error) { calls.Add(1); return f.page, nil }
	adeSync(t, s, id)
	if calls.Load() != 0 {
		t.Fatal("sync bypassed persisted backoff")
	}
	f.fetch = nil
	adeExec(t, s, `UPDATE mdm_apple_ade_servers SET retry_after=NULL WHERE id=$1`, id)
	f.account.OrganizationID = "changed"
	adeSync(t, s, id)
	if adeState(t, s, id).SyncError != "account_changed" || !adePublished(t, s, id)["KEEP1"].Assigned {
		t.Fatal("account change updated inventory")
	}
	f.account.OrganizationID = "synthetic-organization"
	f.pageError = ade.ErrCursor
	adeSync(t, s, id)
	f.pageError = nil
	for _, next := range []string{"cycle1", "cycle2", "cycle1"} {
		f.page = ade.Page{Devices: []ade.Device{{Serial: "STAGED1"}}, Cursor: next, More: true}
		adeSync(t, s, id)
	}
	state = adeState(t, s, id)
	if state.SyncError != "cursor_reset" || state.Pages != 0 || !adePublished(t, s, id)["KEEP1"].Assigned {
		t.Fatal("cursor cycle changed inventory or was not reset")
	}
	var staged int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_ade_fetch WHERE server_id=$1`, id).Scan(&staged); err != nil || staged != 0 {
		t.Fatal("abandoned staging survived reset", err)
	}
}

func TestADEFullPageConflictAndStaleCursorPreserveSnapshot(t *testing.T) {
	s, id, f := adeFixture(t)
	f.page = ade.Page{Devices: []ade.Device{{Serial: "KEEP1"}}, Cursor: "first"}
	adeSync(t, s, id)
	if err := s.changeADEServer(t.Context(), 1, id, "reload", "admin", nil); err != nil {
		t.Fatal(err)
	}
	f.page = ade.Page{Devices: []ade.Device{{Serial: "STAGED1", Model: "First"}}, Cursor: "page1", More: true}
	adeSync(t, s, id)
	f.page = ade.Page{Devices: []ade.Device{{Serial: "STAGED1", Model: "Conflicting"}}, Cursor: "page2"}
	adeSync(t, s, id)
	if adeState(t, s, id).SyncError != "cursor_reset" || !adePublished(t, s, id)["KEEP1"].Assigned {
		t.Fatal("full-page conflict discarded working snapshot")
	}
	adeExec(t, s, `UPDATE mdm_apple_ade_servers SET sync_cursor='stale',cursor_updated_at=clock_timestamp()-interval '7 days' WHERE id=$1`, id)
	f.fetch = func(context.Context, string, bool) (ade.Page, error) {
		t.Error("stale cursor sent to Apple")
		return ade.Page{}, ade.ErrService
	}
	adeSync(t, s, id)
	if adeState(t, s, id).SyncError != "cursor_reset" {
		t.Fatal("stale cursor did not restart full fetch")
	}
}

func TestADEConcurrentOwnersDisableAndPermissionRollback(t *testing.T) {
	s, id, f := adeFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.fetch = func(ctx context.Context, _ string, _ bool) (ade.Page, error) {
		close(entered)
		select {
		case <-release:
			return ade.Page{Devices: []ade.Device{{Serial: "ONLY1"}}, Cursor: "done"}, nil
		case <-ctx.Done():
			return ade.Page{}, ctx.Err()
		}
	}
	done := make(chan error, 1)
	go func() { done <- s.syncADEServer(t.Context(), 1, id) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("owner did not enter service")
	}
	other, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if err := s.syncADEServer(other, 1, id); err != nil {
		t.Error("concurrent owner did not skip locked row", err)
	}
	disabled := make(chan error, 1)
	go func() { disabled <- s.changeADEServer(t.Context(), 1, id, "disable", "admin", nil) }()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-disabled; err != nil {
		t.Fatal(err)
	}
	if adeState(t, s, id).Status != "disabled" || len(adePublished(t, s, id)) != 1 {
		t.Fatal("late response overwrote disabled status or lost history")
	}
	deny := func(context.Context, *sql.Tx) error { return access.ErrDenied }
	if _, err := s.createADEServer(t.Context(), 1, "Denied", "admin", deny); !errors.Is(err, access.ErrDenied) {
		t.Fatal("create ignored authorization")
	}
	if err := s.changeADEServer(t.Context(), 1, id, "sync", "admin", deny); !errors.Is(err, access.ErrDenied) {
		t.Fatal("change ignored authorization")
	}
	if err := s.importADEToken(t.Context(), 1, id, nil, "admin", deny); !errors.Is(err, access.ErrDenied) {
		t.Fatal("import ignored authorization")
	}
	if _, err := s.CreateADEServer(t.Context(), 1, "Denied", "admin", nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("public mutation allowed missing access store")
	}
}

func TestADEInventoryPaginationAndSafeMetadata(t *testing.T) {
	s, id, f := adeFixture(t)
	f.page = ade.Page{Cursor: "done"}
	for i := 0; i < 101; i++ {
		f.page.Devices = append(f.page.Devices, ade.Device{Serial: fmt.Sprintf("SYNTHETIC%03d", i), Model: "<script>synthetic</script>"})
	}
	adeSync(t, s, id)
	first, next, err := s.ADEDevices(t.Context(), 1, id, "")
	if err != nil || len(first) != 100 || next != "SYNTHETIC099" {
		t.Fatal("bad first page", err)
	}
	last, next, err := s.ADEDevices(t.Context(), 1, id, next)
	if err != nil || len(last) != 1 || last[0].Serial != "SYNTHETIC100" || next != "" {
		t.Fatal("bad last page", err)
	}
	servers, err := s.ADEServers(t.Context(), 2)
	if err != nil || len(servers) != 0 {
		t.Fatal("cross-tenant metadata readable", err)
	}
	encoded, err := json.Marshal(adeState(t, s, id))
	if err != nil || strings.Contains(string(encoded), "synthetic-access") || strings.Contains(string(encoded), "private_key") {
		t.Fatal("metadata exposes credentials", err)
	}
}

func TestADEMutationsRecheckRevokedOrganizationPermission(t *testing.T) {
	s, id, _ := adeFixture(t)
	adeExec(t, s, `CREATE TABLE users(uid TEXT PRIMARY KEY); INSERT INTO users VALUES('admin'),('ade-admin')`)
	p, err := access.NewStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = p.Bootstrap(t.Context(), "admin"); err != nil {
		t.Fatal(err)
	}
	if err = p.ReplaceGrants(t.Context(), "admin", "ade-admin", 0, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}); err != nil {
		t.Fatal(err)
	}
	cached, err := p.Principal(t.Context(), "ade-admin")
	if err != nil || !cached.Can(access.ManageCertificates, access.Scope{TenantID: 1}) {
		t.Fatal("fixture lacks authority", err)
	}
	if err = p.ReplaceGrants(t.Context(), "admin", "ade-admin", cached.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: 1}}}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ADEServerCertificate(t.Context(), 1, id, "ade-admin", p); !errors.Is(err, access.ErrDenied) {
		t.Fatal("stale authority downloaded certificate", err)
	}
	if err = s.ChangeADEServer(t.Context(), 1, id, "disable", "ade-admin", p); !errors.Is(err, access.ErrDenied) {
		t.Fatal("stale authority disabled connection", err)
	}
	if err = s.ImportADEToken(t.Context(), 1, id, nil, "ade-admin", p); !errors.Is(err, access.ErrDenied) {
		t.Fatal("stale authority imported credential", err)
	}
	if _, err = s.CreateADEServer(t.Context(), 1, "Denied", "ade-admin", p); !errors.Is(err, access.ErrDenied) {
		t.Fatal("stale authority created connection", err)
	}
	if adeState(t, s, id).Status != "connected" {
		t.Fatal("revoked authority modified connection")
	}
}

func TestADERenewalPersistsAppleBackoffWithoutReplacingCredential(t *testing.T) {
	s, id, f := adeFixture(t)
	renewal := adeTokenEnvelope(t, s, 1, id, time.Now().Add(48*time.Hour))
	var old []byte
	if err := s.db.QueryRow(`SELECT token FROM mdm_apple_ade_servers WHERE id=$1`, id).Scan(&old); err != nil {
		t.Fatal(err)
	}
	f.accountError = &ade.RetryError{After: 48 * time.Hour}
	var retry *ade.RetryError
	if err := s.importADEToken(t.Context(), 1, id, renewal, "admin", nil); !errors.As(err, &retry) {
		t.Fatal("Apple throttle not returned", err)
	}
	state := adeState(t, s, id)
	if state.RetryAfter == nil || state.RetryAfter.Before(time.Now().Add(47*time.Hour)) {
		t.Fatal("renewal lost retry deadline")
	}
	f.accountError = nil
	if err := s.importADEToken(t.Context(), 1, id, renewal, "admin", nil); !errors.As(err, &retry) {
		t.Fatal("renewal bypassed Apple backoff", err)
	}
	var actual []byte
	if err := s.db.QueryRow(`SELECT token FROM mdm_apple_ade_servers WHERE id=$1`, id).Scan(&actual); err != nil || !bytes.Equal(actual, old) {
		t.Fatal("throttled renewal changed credential", err)
	}
}
