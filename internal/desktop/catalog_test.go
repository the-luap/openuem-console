package desktop

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment/artifacts"
)

type catalogTestFixture struct {
	store     *Store
	catalog   *Catalog
	directory string
	public    ed25519.PublicKey
	private   ed25519.PrivateKey
	content   []byte
	manifest  artifacts.Manifest
}

func newCatalogFixture(t *testing.T) *catalogTestFixture {
	t.Helper()
	s := desktopStore(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(private) })
	directory := t.TempDir()
	catalog, err := NewCatalog(s.db, directory, []ed25519.PublicKey{public})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { catalog.Close() })
	content := []byte("non-executable installer integrity fixture")
	digest := sha256.Sum256(content)
	m := artifacts.Manifest{Schema: artifacts.Schema, Sequence: 42, Version: "0.12.0", PublishedAt: time.Now().Add(-time.Hour).UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(), Artifacts: []artifacts.Artifact{{Platform: "windows", Architecture: "amd64", Format: "msi", Filename: "openuem-agent-0.12.0-windows-amd64.msi", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])}}}
	return &catalogTestFixture{store: s, catalog: catalog, directory: directory, public: public, private: private, content: content, manifest: m}
}

func (f *catalogTestFixture) prepare(t *testing.T, m artifacts.Manifest) ([]byte, *artifacts.Verified, string) {
	t.Helper()
	data, err := artifacts.Sign(m, f.private, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := artifacts.Verify(data, []ed25519.PublicKey{f.public}, time.Now(), artifacts.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(f.directory, verified.Digest())
	if err = os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, m.Artifacts[0].Filename)
	if err = os.WriteFile(path, f.content, 0644); err != nil {
		t.Fatal(err)
	}
	return data, verified, path
}

func TestCatalogPersistsApprovalAcrossRestartAndServesTheVerifiedFile(t *testing.T) {
	f := newCatalogFixture(t)
	ctx := context.Background()
	if _, err := f.catalog.Current(ctx); !errors.Is(err, ErrNoRelease) {
		t.Fatal("fresh catalog exposes a release", err)
	}
	data, expected, path := f.prepare(t, f.manifest)
	// NewCatalog owns its trusted key bytes independently of the caller.
	f.public[0] ^= 1
	accepted, err := f.catalog.Accept(ctx, data, "server-admin")
	if err != nil || accepted.Digest() != expected.Digest() {
		t.Fatal("could not approve verified package", err)
	}
	f.public[0] ^= 1
	if err = f.catalog.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewCatalog(f.store.db, f.directory, []ed25519.PublicKey{f.public})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if accepted, err = restarted.Accept(ctx, data, "server-admin"); err != nil || accepted.Checkpoint() != expected.Checkpoint() {
		t.Fatal("restart lost the accepted checkpoint", err)
	}
	file, target, err := restarted.OpenPackage(ctx, expected.Digest(), "windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if target.Size != int64(len(f.content)) {
		t.Fatal("incorrect approved download metadata")
	}
	replacement := path + ".next"
	if err = os.WriteFile(replacement, bytes.Repeat([]byte("x"), len(f.content)), 0644); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(file)
	if err != nil || !bytes.Equal(actual, f.content) {
		t.Fatal("download reopened a replaced filename", err)
	}
	if _, _, err = restarted.OpenPackage(ctx, expected.Digest(), "windows", "amd64"); !errors.Is(err, ErrReleaseFiles) {
		t.Fatal("served replacement bytes outside the approved digest", err)
	}
	if _, _, err = restarted.OpenPackage(ctx, expected.Digest(), "windows", "arm64"); !errors.Is(err, artifacts.ErrTarget) {
		t.Fatal("selected a fallback architecture", err)
	}
	var events int
	if err = f.store.db.QueryRow(`SELECT count(*) FROM uem_desktop_release_audit WHERE actor='server-admin' AND action='release.accept'`).Scan(&events); err != nil || events != 2 {
		t.Fatal("release acceptance was not audited", events, err)
	}
}

func TestCatalogRejectsMissingChangedAndLinkedPackagesWithoutAdvancingState(t *testing.T) {
	for _, kind := range []string{"missing", "truncated", "changed", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newCatalogFixture(t)
			data, _, path := f.prepare(t, f.manifest)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "truncated":
				if err := os.WriteFile(path, f.content[:len(f.content)-1], 0644); err != nil {
					t.Fatal(err)
				}
			case "changed":
				if err := os.WriteFile(path, bytes.Repeat([]byte("x"), len(f.content)), 0644); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				outside := filepath.Join(t.TempDir(), "outside.msi")
				if err := os.WriteFile(outside, f.content, 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.catalog.Accept(context.Background(), data, "server-admin"); !errors.Is(err, ErrReleaseFiles) {
				t.Fatal("accepted an unavailable or changed installer", err)
			}
			if _, err := f.catalog.Current(context.Background()); !errors.Is(err, ErrNoRelease) {
				t.Fatal("failed approval advanced the checkpoint", err)
			}
			var count int
			if err := f.store.db.QueryRow(`SELECT count(*) FROM uem_desktop_releases`).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed approval persisted a release", err)
			}
		})
	}
}

func TestConcurrentCatalogApprovalsWithdrawalAndSequenceReuse(t *testing.T) {
	f := newCatalogFixture(t)
	ctx := context.Background()
	const count = 8
	data := make([][]byte, count)
	approved := make([]*artifacts.Verified, count)
	for i := range count {
		m := f.manifest
		m.Sequence += uint64(i)
		data[i], approved[i], _ = f.prepare(t, m)
	}
	ready := make(chan struct{})
	results := make(chan error, count)
	var work sync.WaitGroup
	for i := range count {
		work.Go(func() { <-ready; _, err := f.catalog.Accept(ctx, data[i], "release-pipeline"); results <- err })
	}
	close(ready)
	work.Wait()
	close(results)
	for err := range results {
		if err != nil && !errors.Is(err, artifacts.ErrRollback) {
			t.Fatal("concurrent approval failed outside the checkpoint invariant", err)
		}
	}
	current, err := f.catalog.Current(ctx)
	if err != nil || current.Checkpoint() != approved[count-1].Checkpoint() {
		t.Fatal("a concurrent approval lowered the final sequence", err)
	}
	m := current.Manifest()
	m.PublishedAt = m.PublishedAt.Add(time.Minute)
	equivocation, _, _ := f.prepare(t, m)
	if _, err = f.catalog.Accept(ctx, equivocation, "release-pipeline"); !errors.Is(err, artifacts.ErrRollback) {
		t.Fatal("reused an accepted sequence for different metadata", err)
	}
	if err = f.catalog.Withdraw(ctx, current.Digest(), "server-admin"); err != nil {
		t.Fatal(err)
	}
	if err = f.catalog.Withdraw(ctx, current.Digest(), "server-admin"); err != nil {
		t.Fatal("identical withdrawal was not idempotent", err)
	}
	if err = f.store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = f.catalog.Current(ctx); !errors.Is(err, ErrWithdrawn) {
		t.Fatal("migration restored a withdrawn release", err)
	}
	if _, err = f.catalog.Accept(ctx, data[count-1], "release-pipeline"); !errors.Is(err, ErrWithdrawn) {
		t.Fatal("an identical publish undid an administrator withdrawal", err)
	}
	if _, err = f.catalog.Accept(ctx, data[0], "release-pipeline"); !errors.Is(err, artifacts.ErrRollback) {
		t.Fatal("withdrawal reset the monotonic checkpoint", err)
	}
	m = f.manifest
	m.Sequence += count
	newData, newApproved, _ := f.prepare(t, m)
	if _, err = f.catalog.Accept(ctx, newData, "release-pipeline"); err != nil {
		t.Fatal("could not accept a new release after withdrawal", err)
	}
	if _, _, err = f.catalog.OpenPackage(ctx, current.Digest(), "windows", "amd64"); !errors.Is(err, ErrNoRelease) {
		t.Fatal("old invitation could download a superseded release", err)
	}
	if err = f.catalog.Withdraw(ctx, current.Digest(), "server-admin"); !errors.Is(err, ErrNoRelease) {
		t.Fatal("stale withdrawal changed the current release", err)
	}
	if current, err = f.catalog.Current(ctx); err != nil || current.Digest() != newApproved.Digest() {
		t.Fatal("stale withdrawal affected the new release", err)
	}
	var events int
	if err = f.store.db.QueryRow(`SELECT count(*) FROM uem_desktop_release_audit WHERE action='release.withdraw'`).Scan(&events); err != nil || events != 1 {
		t.Fatal("withdrawal audit was absent or duplicated", events, err)
	}
}

func TestCatalogRechecksStoredSignaturesAndCancellation(t *testing.T) {
	f := newCatalogFixture(t)
	ctx := context.Background()
	data, verified, _ := f.prepare(t, f.manifest)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.catalog.Accept(cancelled, data, "release-pipeline"); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation during artifact validation", err)
	}
	if _, err := f.catalog.Current(ctx); !errors.Is(err, ErrNoRelease) {
		t.Fatal("cancelled acceptance changed state", err)
	}
	if _, err := f.catalog.Accept(ctx, data, "release-pipeline"); err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewCatalog(f.store.db, f.directory, []ed25519.PublicKey{other})
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Close()
	if _, err = rotated.Current(ctx); !errors.Is(err, artifacts.ErrUntrusted) {
		t.Fatal("accepted stored bytes signed by a removed trust key", err)
	}
	if _, err = f.store.db.Exec(`UPDATE uem_desktop_releases SET envelope=$1 WHERE digest=$2`, []byte(`{"schema":1,"key_id":"untrusted","payload":"e30","signature":"bad"}`), verified.Digest()); err != nil {
		t.Fatal(err)
	}
	if _, err = f.catalog.Current(ctx); !errors.Is(err, artifacts.ErrUntrusted) {
		t.Fatal("trusted changed database bytes without checking the signature", err)
	}
}
