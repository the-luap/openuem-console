package apple

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/software/winget"
)

func windowsSourceFixture(t *testing.T) (*Store, *access.Store, *SoftwareVersion, WindowsSoftwareInput, winget.Snapshot) {
	t.Helper()
	s, permissions := windowsSoftwareStore(t)
	input := testWindowsSoftware("windows-winget")
	v, err := s.PublishWindowsSoftware(t.Context(), Scope{TenantID: 1}, uuid.NewString(), input, "admin", permissions)
	if err != nil {
		t.Fatal(err)
	}
	return s, permissions, v, input, windowsSourceSnapshot(t, input)
}

func windowsSourceSnapshot(t *testing.T, input WindowsSoftwareInput) winget.Snapshot {
	t.Helper()
	content := fmt.Sprintf("PackageIdentifier: %s\nPackageVersion: %s\nInstallerType: wix\nScope: machine\nInstallers:\n- Architecture: x64\n  InstallerUrl: https://example.invalid/private-download.msi?token=source-secret\n  InstallerSha256: %s\n  ProductCode: '%s'\n- Architecture: arm64\n  InstallerUrl: https://example.invalid/other.msi\n  InstallerSha256: %s\n  ProductCode: '{AABBCCDD-0000-4000-8000-000000000002}'\nManifestType: installer\nManifestVersion: 1.12.0\n", input.Identifier, input.Version, strings.Repeat("A", 64), input.Detection.ProductCode, strings.Repeat("b", 64))
	snapshot := winget.Snapshot{Coordinate: winget.Coordinate{Identifier: input.Identifier, Version: input.Version}, Commit: strings.Repeat("a", 40), Path: "manifests/" + strings.ToLower(input.Identifier[:1]) + "/" + strings.ReplaceAll(input.Identifier, ".", "/") + "/" + input.Version + "/" + input.Identifier + ".installer.yaml", Content: []byte(content)}
	sum := sha256.Sum256(snapshot.Content)
	snapshot.SHA256 = hex.EncodeToString(sum[:])
	if _, err := snapshot.Inspect(); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func fixedWindowsSource(snapshot winget.Snapshot) func(context.Context, winget.Coordinate) (*winget.Snapshot, error) {
	return func(ctx context.Context, coordinate winget.Coordinate) (*winget.Snapshot, error) {
		if coordinate != snapshot.Coordinate {
			return nil, winget.ErrCoordinate
		}
		return &snapshot, ctx.Err()
	}
}

func TestWindowsSoftwareSourceDerivedRevisionUsesExactEncryptedDispatch(t *testing.T) {
	for _, operation := range []string{"install", "remove"} {
		t.Run(operation, func(t *testing.T) {
			f := newWindowsDispatchFixture(t, "windows-winget", operation)
			ctx, scope := t.Context(), Scope{TenantID: 1, SiteID: 1}
			input := testWindowsSoftware("windows-winget")
			input.Identifier = "Vendor.Executable"
			snapshot := windowsSourceSnapshot(t, input)
			id := uuid.NewString()
			original := f.version.ID
			if _, err := f.store.ResolveWindowsSoftwareSource(ctx, Scope{TenantID: 1}, original, id, "admin", f.permissions, fixedWindowsSource(snapshot)); err != nil {
				t.Fatal(err)
			}
			review, err := f.store.ReviewWindowsSoftwareSource(ctx, Scope{TenantID: 1}, original, id, "admin", f.permissions)
			if err != nil {
				t.Fatal(err)
			}
			derived, err := f.store.ApproveWindowsSoftwareSource(ctx, Scope{TenantID: 1}, original, id, uuid.NewString(), 0, review.Options[0].ReviewHash, "admin", f.permissions)
			if err != nil {
				t.Fatal(err)
			}
			f.assertNoDispatch(t)
			if err = f.store.CancelWindowsSoftwarePreparation(ctx, scope, original, f.request.ID, "operator", f.permissions); err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.db.Exec(`UPDATE uem_software_versions SET withdrawn_at=clock_timestamp() WHERE id=$1`, original); err != nil {
				t.Fatal(err)
			}
			f.version = derived
			f.request, err = f.store.PrepareWindowsSoftware(ctx, scope, uuid.NewString(), derived.ID, f.identity.DeviceID, operation, "operator", f.permissions)
			if err != nil {
				t.Fatal(err)
			}
			dispatchReview := f.review(t)
			if _, err = f.store.DispatchWindowsSoftware(ctx, scope, derived.ID, f.request.ID, uuid.NewString(), dispatchReview.ReviewHash, "operator", f.permissions); err != nil {
				t.Fatal(err)
			}
			reply, err := f.call(t, enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID})
			if err != nil || reply.Task == nil {
				t.Fatal("derived task unavailable", err)
			}
			secret, err := f.key.Open(*reply.Task, f.authority, f.recipient.Identity, f.recipient.ID, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Close()
			expected, err := winget.MSIPlan(snapshot, 0, sourceMSITarget(input), operation)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := expected.Digest()
			got, _ := secret.Plan.Digest()
			if want != got || reply.Task.Context.RevisionID != derived.ID || reply.Task.Context.PreparationID != f.request.ID {
				t.Fatal("derived dispatch changed approved source intent")
			}
			detail, err := f.store.ReadSoftwareVersion(ctx, scope, derived.ID, "reader", f.permissions)
			if err != nil || detail.WinGetSource == nil || detail.WinGetSource.SourceVersionID != original {
				t.Fatal("original withdrawal erased derived provenance", err)
			}
		})
	}
}

func TestWindowsSoftwareSourceMigrationPreservesExistingRevisionsAndPreparations(t *testing.T) {
	s, p, v, identity, _ := windowsRequestFixtureBeforeMigration(t, "migrations/041_windows_winget_sources.sql")
	ctx := t.Context()
	input := testWindowsSoftware("windows-winget")
	if _, err := s.PublishWindowsSoftware(ctx, Scope{TenantID: 1}, uuid.NewString(), input, "admin", p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareWindowsSoftware(ctx, Scope{TenantID: 1, SiteID: 1}, uuid.NewString(), v.ID, identity.DeviceID, "install", "operator", p); err != nil {
		t.Fatal(err)
	}
	snapshot := func() []byte {
		t.Helper()
		var data []byte
		if err := s.db.QueryRow(`SELECT json_build_object('versions',(SELECT json_agg(row_to_json(v) ORDER BY v.id) FROM uem_software_versions v),'requests',(SELECT json_agg(row_to_json(r) ORDER BY r.id) FROM uem_windows_software_requests r))`).Scan(&data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	before := snapshot()
	for range 2 {
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(before, snapshot()) {
		t.Fatal("source migration changed existing approval or preparation")
	}
	var count int
	if err := s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_windows_software_sources)+(SELECT count(*) FROM uem_windows_software_source_approvals)+(SELECT count(*) FROM uem_agent_software_tasks)`).Scan(&count); err != nil || count != 0 {
		t.Fatal("migration captured, approved or dispatched software", err)
	}
	detail, err := s.ReadSoftwareVersion(ctx, Scope{TenantID: 1, SiteID: 1}, v.ID, "reader", p)
	if err != nil || detail.WinGetSource != nil {
		t.Fatal("ordinary historical MSI gained source provenance", err)
	}
}

func TestWindowsSoftwareSourceExpiryAfterAuditRollsBackApproval(t *testing.T) {
	s, p, v, _, snapshot := windowsSourceFixture(t)
	ctx, scope, id := t.Context(), Scope{TenantID: 1}, uuid.NewString()
	if _, err := s.ResolveWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", p, fixedWindowsSource(snapshot)); err != nil {
		t.Fatal(err)
	}
	alterSourceEnvelope(t, s, id, func(e *windowsSourceEnvelope) {
		e.ExpiresAt = time.Now().UTC().Add(3 * time.Second).Truncate(time.Second)
	})
	review, err := s.ReviewWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", p)
	if err != nil || len(review.Options) != 1 {
		t.Fatal("owned near-deadline review unavailable", err)
	}
	if _, err = s.db.Exec(`CREATE FUNCTION delay_source_approval() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='software.windows.source.approve' THEN PERFORM pg_sleep(GREATEST(EXTRACT(EPOCH FROM ((SELECT expires_at FROM uem_windows_software_sources WHERE id=NEW.resource_id::uuid)-clock_timestamp())),0)+0.02); END IF; RETURN NEW; END $$; CREATE TRIGGER delay_source_approval BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION delay_source_approval()`); err != nil {
		t.Fatal(err)
	}
	result, err := s.ApproveWindowsSoftwareSource(ctx, scope, v.ID, id, uuid.NewString(), 0, review.Options[0].ReviewHash, "admin", p)
	if !errors.Is(err, ErrConflict) || result != nil {
		t.Fatal("approval committed after deadline", err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_windows_software_source_approvals)+(SELECT count(*) FROM uem_software_versions WHERE kind='windows-msi')+(SELECT count(*) FROM mdm_apple_audit WHERE action='software.windows.source.approve')`).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired approval partly committed", err)
	}
}

func TestWindowsSoftwareSourceCompetingApprovalIDsAndOriginalRevisionOwnership(t *testing.T) {
	s, p, v, input, snapshot := windowsSourceFixture(t)
	ctx, scope, id := t.Context(), Scope{TenantID: 1}, uuid.NewString()
	if _, err := s.ResolveWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", p, fixedWindowsSource(snapshot)); err != nil {
		t.Fatal(err)
	}
	other, err := s.PublishWindowsSoftware(ctx, scope, uuid.NewString(), input, "admin", p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ResolveWindowsSoftwareSource(ctx, scope, other.ID, id, "admin", p, func(context.Context, winget.Coordinate) (*winget.Snapshot, error) {
		t.Error("conflicting capture ID fetched another source")
		return nil, winget.ErrSource
	}); !errors.Is(err, ErrConflict) {
		t.Fatal("capture ID rebound to another original revision or lost conflict guidance", err)
	}
	review, err := s.ReviewWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", p)
	if err != nil {
		t.Fatal(err)
	}
	var work sync.WaitGroup
	var winners atomic.Int32
	for range 6 {
		work.Go(func() {
			_, err := s.ApproveWindowsSoftwareSource(ctx, scope, v.ID, id, uuid.NewString(), 0, review.Options[0].ReviewHash, "admin", p)
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Error(err)
			}
		})
	}
	work.Wait()
	if winners.Load() != 1 {
		t.Fatal("competing approval IDs produced multiple revisions")
	}
	page, err := s.ReadWindowsSoftwareSources(ctx, scope, v.ID, "", "admin", p)
	if err != nil || len(page.Sources) != 1 || page.Sources[0].Approval == nil {
		t.Fatal("winner lost provenance", err)
	}
	derived := page.Sources[0].Approval.VersionID
	// Simulate restored inconsistent public metadata only in this owned schema.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`ALTER TABLE uem_software_versions DISABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE uem_software_versions SET name='Changed public name' WHERE id=$1`, derived); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`ALTER TABLE uem_software_versions ENABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadSoftwareVersion(ctx, scope, derived, "admin", p); err == nil {
		t.Fatal("tampered public revision retained verified source attribution")
	}
	if _, err = s.ReadWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", p); err == nil {
		t.Fatal("source evidence concealed tampered derived revision")
	}
}

func TestWindowsSoftwareSourceCaptureReviewAndImmutableApproval(t *testing.T) {
	s, permissions, v, input, snapshot := windowsSourceFixture(t)
	ctx, scope, id := t.Context(), Scope{TenantID: 1}, uuid.NewString()
	var calls atomic.Int32
	fetch := func(ctx context.Context, c winget.Coordinate) (*winget.Snapshot, error) {
		calls.Add(1)
		return fixedWindowsSource(snapshot)(ctx, c)
	}
	r, err := s.ResolveWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", permissions, fetch)
	if err != nil || r.Commit != snapshot.Commit || r.ManifestSHA256 != snapshot.SHA256 {
		t.Fatalf("capture: %v", err)
	}
	if calls.Load() != 1 || r.Approval != nil || !r.ExpiresAt.After(r.CreatedAt) || r.ExpiresAt.Sub(r.CreatedAt) > 15*time.Minute {
		t.Fatal("capture changed approval or lifetime")
	}
	var sealed []byte
	if err = s.db.QueryRow(`SELECT encrypted_snapshot FROM uem_windows_software_sources WHERE id=$1`, id).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("source-secret")) || bytes.Contains(sealed, []byte("InstallerUrl")) {
		t.Fatal("source stored without encryption")
	}
	public, _ := json.Marshal(r)
	if bytes.Contains(public, []byte("source-secret")) || bytes.Contains(public, []byte("private-download")) {
		t.Fatal("capture leaked source data")
	}
	review, err := s.ReviewWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", permissions)
	if err != nil || len(review.Options) != 1 || review.Options[0].Index != 0 || review.Options[0].DownloadHost != "example.invalid" || review.InstallerCount != 2 {
		t.Fatalf("review: %v", err)
	}
	public, _ = json.Marshal(review)
	if bytes.Contains(public, []byte("source-secret")) || bytes.Contains(public, []byte("private-download")) {
		t.Fatal("review leaked source path or token")
	}
	approval := uuid.NewString()
	hash := review.Options[0].ReviewHash
	derived, err := s.ApproveWindowsSoftwareSource(ctx, scope, v.ID, id, approval, 0, hash, "admin", permissions)
	if err != nil || derived.Kind != "windows-msi" || derived.Identifier != input.Identifier || derived.SHA256 != strings.Repeat("a", 64) || derived.Windows.Detection != input.Detection {
		t.Fatalf("source approval: %v", err)
	}
	var originalKind string
	if err = s.db.QueryRow(`SELECT kind FROM uem_software_versions WHERE id=$1`, v.ID).Scan(&originalKind); err != nil || originalKind != "windows-winget" {
		t.Fatal("original coordinate rewritten")
	}
	for range 2 {
		retry, err := s.ResolveWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", permissions, fetch)
		if err != nil || retry.Approval == nil || retry.Approval.VersionID != derived.ID || calls.Load() != 1 {
			t.Fatal("capture retry refetched or lost history", err)
		}
		again, err := s.ApproveWindowsSoftwareSource(ctx, scope, v.ID, id, approval, 0, hash, "admin", permissions)
		if err != nil || again.ID != derived.ID {
			t.Fatal("approval retry changed revision", err)
		}
	}
	page, err := s.ReadWindowsSoftwareSources(ctx, Scope{TenantID: 1, SiteID: 1}, v.ID, "", "reader", permissions)
	if err != nil || len(page.Sources) != 1 || page.Sources[0].Approval == nil || page.Sources[0].Approval.VersionID != derived.ID {
		t.Fatal("reader provenance", err)
	}
	for _, revision := range []string{v.ID, derived.ID} {
		detail, e := s.ReadSoftwareVersion(ctx, Scope{TenantID: 1, SiteID: 1}, revision, "reader", permissions)
		if e != nil || (detail.WinGetSource != nil) != (revision == derived.ID) {
			t.Fatal("catalog detail provenance", e)
		}
		if detail.WinGetSource != nil && (detail.WinGetSource.ID != id || detail.WinGetSource.SourceVersionID != v.ID) {
			t.Fatal("catalog detail changed source")
		}
		public, _ = json.Marshal(detail)
		if bytes.Contains(public, []byte("source-secret")) || bytes.Contains(public, []byte("private-download")) {
			t.Fatal("detail exposed source execution data")
		}
	}
	focused, e := s.ReadWindowsSoftwareSource(ctx, Scope{TenantID: 1, SiteID: 1}, v.ID, id, "reader", permissions)
	if e != nil || !focused.Focused || len(focused.Sources) != 1 || focused.Sources[0].Approval.VersionID != derived.ID {
		t.Fatal("focused source evidence", e)
	}
	if _, e = s.ReadWindowsSoftwareSource(ctx, Scope{TenantID: 2}, v.ID, id, "admin", permissions); !errors.Is(e, ErrNotFound) {
		t.Fatal("focused evidence crossed tenant", e)
	}
	var requests, approvals, audits int
	if err = s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_windows_software_requests),(SELECT count(*) FROM uem_windows_software_source_approvals),(SELECT count(*) FROM mdm_apple_audit WHERE action='software.windows.source.approve')`).Scan(&requests, &approvals, &audits); err != nil || requests != 0 || approvals != 1 || audits != 1 {
		t.Fatal("source approval executed work or duplicated audit", err)
	}
	for _, table := range []string{"uem_windows_software_sources", "uem_windows_software_source_approvals"} {
		for _, command := range []string{"DELETE FROM " + table, "TRUNCATE " + table + " CASCADE", "UPDATE " + table + " SET actor='second-admin'"} {
			if _, err = s.db.Exec(command); err == nil {
				t.Fatal("source history was mutable")
			}
		}
	}
	// Independent withdrawals do not erase source history or restore approval.
	if _, err = s.db.Exec(`UPDATE uem_software_versions SET withdrawn_at=clock_timestamp() WHERE id IN ($1,$2)`, v.ID, derived.ID); err != nil {
		t.Fatal(err)
	}
	again, err := s.ApproveWindowsSoftwareSource(ctx, scope, v.ID, id, approval, 0, hash, "admin", permissions)
	if err != nil || again.WithdrawnAt == nil {
		t.Fatal("historical retry restored withdrawal", err)
	}
	page, err = s.ReadWindowsSoftwareSources(ctx, Scope{TenantID: 1, SiteID: 1}, v.ID, "", "reader", permissions)
	if err != nil || page.Sources[0].Approval.WithdrawnAt == nil {
		t.Fatal("withdrawn provenance hidden", err)
	}
}

func TestWindowsSoftwareSourceConcurrencyAndExactRequestOwnership(t *testing.T) {
	s, permissions, v, _, snapshot := windowsSourceFixture(t)
	ctx, scope, id := t.Context(), Scope{TenantID: 1}, uuid.NewString()
	const workers = 6
	started := make(chan struct{}, workers)
	release := make(chan struct{})
	fetch := func(ctx context.Context, c winget.Coordinate) (*winget.Snapshot, error) {
		started <- struct{}{}
		select {
		case <-release:
			return fixedWindowsSource(snapshot)(ctx, c)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	results := make(chan *WindowsSoftwareSource, workers)
	errs := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			r, e := s.ResolveWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", permissions, fetch)
			results <- r
			errs <- e
		}()
	}
	for range workers {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("source fetch retained a transaction lock")
		}
	}
	close(release)
	group.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for result := range results {
		if result.ID != id || result.ManifestSHA256 != snapshot.SHA256 {
			t.Fatal("competing capture changed retained source")
		}
	}
	review, err := s.ReviewWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", permissions)
	if err != nil {
		t.Fatal(err)
	}
	approval := uuid.NewString()
	hash := review.Options[0].ReviewHash
	ids := make(chan string, workers)
	errs = make(chan error, workers)
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			r, e := s.ApproveWindowsSoftwareSource(ctx, scope, v.ID, id, approval, 0, hash, "admin", permissions)
			if r != nil {
				ids <- r.ID
			}
			errs <- e
		}()
	}
	group.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first string
	for id := range ids {
		if first == "" {
			first = id
		}
		if first != id {
			t.Fatal("exact concurrent approvals created different revisions")
		}
	}
	if _, err = s.ApproveWindowsSoftwareSource(ctx, scope, v.ID, id, uuid.NewString(), 0, hash, "admin", permissions); !errors.Is(err, ErrConflict) {
		t.Fatal("another approval ID reused candidate")
	}
	if _, err = s.ResolveWindowsSoftwareSource(ctx, scope, v.ID, id, "second-admin", permissions, fixedWindowsSource(snapshot)); !errors.Is(err, ErrConflict) {
		t.Fatal("another actor reused capture")
	}
	if _, err = s.ReviewWindowsSoftwareSource(ctx, scope, v.ID, id, "second-admin", permissions); !errors.Is(err, access.ErrDenied) {
		t.Fatal("another actor received confirmation hash")
	}
	var captures, links, published int
	if err = s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_windows_software_sources),(SELECT count(*) FROM uem_windows_software_source_approvals),(SELECT count(*) FROM mdm_apple_audit WHERE action='software.windows.source.capture')`).Scan(&captures, &links, &published); err != nil || captures != 1 || links != 1 || published != 1 {
		t.Fatal("concurrency lost exactly one captured source and approval", err)
	}
}

func TestWindowsSoftwareSourceRechecksAuthorityAfterFetch(t *testing.T) {
	for _, change := range []string{"revoke", "withdraw", "wrong-coordinate", "bad-content", "source-failure", "nil"} {
		t.Run(change, func(t *testing.T) {
			s, permissions, v, _, snapshot := windowsSourceFixture(t)
			actor := "second-admin"
			fetch := func(ctx context.Context, c winget.Coordinate) (*winget.Snapshot, error) {
				switch change {
				case "revoke":
					state, e := permissions.Principal(ctx, actor)
					if e != nil {
						t.Fatal(e)
					}
					if e = permissions.ReplaceGrants(ctx, "admin", actor, state.Revision, nil); e != nil {
						t.Fatal(e)
					}
				case "withdraw":
					if _, e := s.db.ExecContext(ctx, `UPDATE uem_software_versions SET withdrawn_at=clock_timestamp() WHERE id=$1`, v.ID); e != nil {
						t.Fatal(e)
					}
				case "wrong-coordinate":
					snapshot.Coordinate.Version = "other"
				case "bad-content":
					snapshot.Content[0] = '!'
				case "source-failure":
					return nil, winget.ErrSource
				case "nil":
					return nil, nil
				}
				return &snapshot, nil
			}
			result, err := s.ResolveWindowsSoftwareSource(t.Context(), Scope{TenantID: 1}, v.ID, uuid.NewString(), actor, permissions, fetch)
			if err == nil || result != nil {
				t.Fatal("changed capture admitted")
			}
			var count int
			if e := s.db.QueryRow(`SELECT count(*) FROM uem_windows_software_sources`).Scan(&count); e != nil || count != 0 {
				t.Fatal("failed fetch left partial source", e)
			}
		})
	}
}

func TestWindowsSoftwareSourceAuditRollbackAndAdmission(t *testing.T) {
	for _, action := range []string{"software.windows.source.request", "software.windows.source.capture", "software.windows.source.review", "software.windows.source.read", "software.windows.version.publish", "software.windows.source.approve"} {
		t.Run(action, func(t *testing.T) {
			s, permissions, v, _, snapshot := windowsSourceFixture(t)
			ctx, scope, id := t.Context(), Scope{TenantID: 1}, uuid.NewString()
			var calls int
			fetch := func(ctx context.Context, c winget.Coordinate) (*winget.Snapshot, error) {
				calls++
				return fixedWindowsSource(snapshot)(ctx, c)
			}
			var review *WindowsSoftwareSourceReview
			if action != "software.windows.source.request" && action != "software.windows.source.capture" {
				if _, err := s.ResolveWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", permissions, fetch); err != nil {
					t.Fatal(err)
				}
				var err error
				review, err = s.ReviewWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", permissions)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.db.Exec(`CREATE FUNCTION reject_source_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='` + action + `' THEN RAISE EXCEPTION 'owned audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_source_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_source_audit()`); err != nil {
				t.Fatal(err)
			}
			switch action {
			case "software.windows.source.request", "software.windows.source.capture":
				r, err := s.ResolveWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", permissions, fetch)
				if err == nil || r != nil {
					t.Fatal("capture escaped audit rollback")
				}
				var count int
				if err = s.db.QueryRow(`SELECT count(*) FROM uem_windows_software_sources`).Scan(&count); err != nil || count != 0 {
					t.Fatal("capture partially committed")
				}
				if action == "software.windows.source.request" && calls != 0 {
					t.Fatal("source contacted before request audit committed")
				}
			case "software.windows.source.review":
				r, err := s.ReviewWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", permissions)
				if err == nil || r != nil {
					t.Fatal("review escaped audit rollback")
				}
			case "software.windows.source.read":
				r, err := s.ReadWindowsSoftwareSources(ctx, scope, v.ID, "", "admin", permissions)
				if err == nil || r != nil {
					t.Fatal("history escaped audit rollback")
				}
			default:
				r, err := s.ApproveWindowsSoftwareSource(ctx, scope, v.ID, id, uuid.NewString(), 0, review.Options[0].ReviewHash, "admin", permissions)
				if err == nil || r != nil {
					t.Fatal("approval escaped audit rollback")
				}
				var count int
				if err = s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_windows_software_source_approvals)+(SELECT count(*) FROM uem_software_versions WHERE kind='windows-msi')`).Scan(&count); err != nil || count != 0 {
					t.Fatal("approval or provenance partially committed", err)
				}
			}
		})
	}
}

func TestWindowsSoftwareSourceRejectsStaleReviewAndForeignScope(t *testing.T) {
	s, permissions, v, _, snapshot := windowsSourceFixture(t)
	ctx, scope, id := t.Context(), Scope{TenantID: 1}, uuid.NewString()
	fetch := fixedWindowsSource(snapshot)
	if _, err := s.ResolveWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", permissions, fetch); err != nil {
		t.Fatal(err)
	}
	review, err := s.ReviewWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", permissions)
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []string{"reader", "operator", "unknown"} {
		if _, err := s.ResolveWindowsSoftwareSource(ctx, scope, v.ID, uuid.NewString(), actor, permissions, fetch); !errors.Is(err, access.ErrDenied) {
			t.Fatal("source mutation escaped role", actor, err)
		}
		if _, err := s.ApproveWindowsSoftwareSource(ctx, scope, v.ID, id, uuid.NewString(), 0, review.Options[0].ReviewHash, actor, permissions); !errors.Is(err, access.ErrDenied) {
			t.Fatal("source approval escaped role", actor, err)
		}
	}
	for _, other := range []Scope{{TenantID: 1, SiteID: 1}, {TenantID: 2}} {
		if _, err := s.ResolveWindowsSoftwareSource(ctx, other, v.ID, uuid.NewString(), "admin", permissions, fetch); err == nil {
			t.Fatal("source escaped original organization")
		}
	}
	if _, err := s.ReadWindowsSoftwareSources(ctx, Scope{TenantID: 2}, v.ID, "", "admin", permissions); err == nil {
		t.Fatal("foreign source history disclosed")
	}
	for _, change := range []struct {
		Index int
		Hash  string
	}{{1, review.Options[0].ReviewHash}, {0, strings.Repeat("b", 64)}} {
		if _, err := s.ApproveWindowsSoftwareSource(ctx, scope, v.ID, id, uuid.NewString(), change.Index, change.Hash, "admin", permissions); err == nil {
			t.Fatal("changed review admitted")
		}
	}
	// A normal approval request ID cannot acquire new provenance retroactively.
	genericID := uuid.NewString()
	if _, err = s.PublishWindowsSoftware(ctx, scope, genericID, testWindowsSoftware("windows-msi"), "admin", permissions); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ApproveWindowsSoftwareSource(ctx, scope, v.ID, id, genericID, 0, review.Options[0].ReviewHash, "admin", permissions); !errors.Is(err, ErrConflict) {
		t.Fatal("ordinary approval reattributed")
	}
	if _, err = s.db.Exec(`UPDATE uem_software_versions SET withdrawn_at=clock_timestamp() WHERE id=$1`, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ApproveWindowsSoftwareSource(ctx, scope, v.ID, id, uuid.NewString(), 0, review.Options[0].ReviewHash, "admin", permissions); !errors.Is(err, ErrConflict) {
		t.Fatal("withdrawn coordinate admitted new approval")
	}
}

// Modify only this owned fixture to exercise authenticated historical reads.
func alterSourceEnvelope(t *testing.T, s *Store, id string, change func(*windowsSourceEnvelope)) {
	t.Helper()
	var sealed []byte
	if err := s.db.QueryRow(`SELECT encrypted_snapshot FROM uem_windows_software_sources WHERE id=$1`, id).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	plain, err := s.secrets.open(sealed, secretPurpose(1, id, "windows_winget_source"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	var envelope windowsSourceEnvelope
	if json.Unmarshal(plain, &envelope) != nil {
		t.Fatal("owned envelope")
	}
	change(&envelope)
	wire, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	sealed, err = s.secrets.seal(wire, secretPurpose(1, id, "windows_winget_source"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, query := range []string{`ALTER TABLE uem_windows_software_sources DISABLE TRIGGER uem_windows_software_source_guard`, `UPDATE uem_windows_software_sources SET encrypted_snapshot=$2,created_at=$3,expires_at=$4 WHERE id=$1`, `ALTER TABLE uem_windows_software_sources ENABLE TRIGGER uem_windows_software_source_guard`} {
		var err error
		if strings.HasPrefix(query, "UPDATE") {
			_, err = tx.Exec(query, id, sealed, envelope.CreatedAt, envelope.ExpiresAt)
		} else {
			_, err = tx.Exec(query)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsSoftwareSourceExpiredAndAuthenticatedHistory(t *testing.T) {
	for _, change := range []string{"expired", "actor", "coordinate", "digest", "format"} {
		t.Run(change, func(t *testing.T) {
			s, permissions, v, _, snapshot := windowsSourceFixture(t)
			ctx, scope, id := t.Context(), Scope{TenantID: 1}, uuid.NewString()
			if _, err := s.ResolveWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", permissions, fixedWindowsSource(snapshot)); err != nil {
				t.Fatal(err)
			}
			review, err := s.ReviewWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", permissions)
			if err != nil {
				t.Fatal(err)
			}
			alterSourceEnvelope(t, s, id, func(e *windowsSourceEnvelope) {
				switch change {
				case "format":
					e.FormatVersion = 2
				case "expired":
					e.CreatedAt = time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
					e.ExpiresAt = e.CreatedAt.Add(15 * time.Minute)
				case "actor":
					e.Actor = "second-admin"
				case "coordinate":
					e.Snapshot.Coordinate.Identifier = "Other.Package"
				case "digest":
					e.Snapshot.SHA256 = strings.Repeat("f", 64)
				}
			})
			page, err := s.ReadWindowsSoftwareSources(ctx, scope, v.ID, "", "admin", permissions)
			if change == "expired" {
				if err != nil || len(page.Sources) != 1 {
					t.Fatal("expired history unreadable", err)
				}
				again, err := s.ReviewWindowsSoftwareSource(ctx, scope, v.ID, id, "admin", permissions)
				if err != nil || !again.Expired || len(again.Options) != 0 {
					t.Fatal("expired review offered work", err)
				}
			} else if err == nil || page != nil {
				t.Fatal("altered evidence returned public history")
			}
			if _, err = s.ApproveWindowsSoftwareSource(ctx, scope, v.ID, id, uuid.NewString(), 0, review.Options[0].ReviewHash, "admin", permissions); err == nil {
				t.Fatal("expired or altered evidence admitted")
			}
		})
	}
}

func TestWindowsSoftwareSourceHistoryPagination(t *testing.T) {
	s, permissions, v, _, snapshot := windowsSourceFixture(t)
	ctx, scope := t.Context(), Scope{TenantID: 1}
	for range 53 {
		if _, err := s.ResolveWindowsSoftwareSource(ctx, scope, v.ID, uuid.NewString(), "admin", permissions, fixedWindowsSource(snapshot)); err != nil {
			t.Fatal(err)
		}
	}
	first, err := s.ReadWindowsSoftwareSources(ctx, scope, v.ID, "", "admin", permissions)
	if err != nil || len(first.Sources) != 50 || first.Next == "" {
		t.Fatal("first history page", err)
	}
	second, err := s.ReadWindowsSoftwareSources(ctx, scope, v.ID, first.Next, "admin", permissions)
	if err != nil || len(second.Sources) != 3 || second.Next != "" {
		t.Fatal("second history page", err)
	}
	for _, a := range first.Sources {
		for _, b := range second.Sources {
			if a.ID == b.ID {
				t.Fatal("source history overlapped")
			}
		}
	}
	foreign, err := s.ReadWindowsSoftwareSources(ctx, scope, v.ID, uuid.NewString(), "admin", permissions)
	if err != nil || len(foreign.Sources) != 0 {
		t.Fatal("foreign cursor exposed another page", err)
	}
}
