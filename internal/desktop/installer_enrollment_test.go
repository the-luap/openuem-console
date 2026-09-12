package desktop

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/registry"
)

func prepareInstallerInvitation(t *testing.T, f *catalogTestFixture) (*InstallerInvitation, *enrollment.Request) {
	t.Helper()
	data, verified, _ := f.prepare(t, f.manifest)
	if _, err := f.catalog.Accept(context.Background(), data, "release-pipeline"); err != nil {
		t.Fatal(err)
	}
	options := registry.InvitationOptions{Scope: registry.Scope{TenantID: 1, SiteID: 1}, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(30 * time.Minute)}
	invitation, err := f.store.InviteInstaller(context.Background(), f.catalog, options, verified.Digest(), "https://uem.example.test", "organization-admin")
	if err != nil {
		t.Fatal(err)
	}
	token := invitation.URL[strings.LastIndex(invitation.URL, "/")+1:]
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	request, err := keys.Request(token, "windows", "amd64", "Approved Windows endpoint")
	if err != nil {
		t.Fatal(err)
	}
	return invitation, request
}

func TestInstallerInvitationBindsApprovedTargetAndRollsBackInvalidScopeOriginAndExpiry(t *testing.T) {
	f := newCatalogFixture(t)
	ctx := context.Background()
	invitation, request := prepareInstallerInvitation(t, f)
	var selected string
	if err := f.store.db.QueryRow(`SELECT release_digest FROM uem_desktop_invitation_releases WHERE invitation_id=$1`, invitation.ID).Scan(&selected); err != nil || selected != invitation.ReleaseDigest {
		t.Fatal("invitation lost its exact release binding", err)
	}
	for _, change := range []struct {
		name, origin string
		modify       func(*registry.InvitationOptions)
		want         error
	}{
		{"foreign site", "https://uem.example.test", func(o *registry.InvitationOptions) { o.SiteID = 2 }, registry.ErrNotFound},
		{"other configured origin", "https://other.example.test", func(*registry.InvitationOptions) {}, registry.ErrInvalid},
		{"expiry outlives release", "https://uem.example.test", func(o *registry.InvitationOptions) { o.ExpiresAt = time.Now().Add(2 * time.Hour) }, registry.ErrInvalid},
		{"unsupported CPU", "https://uem.example.test", func(o *registry.InvitationOptions) { o.Architecture = "arm64" }, artifacts.ErrTarget},
	} {
		t.Run(change.name, func(t *testing.T) {
			options := invitation.InvitationOptions
			change.modify(&options)
			if _, err := f.store.InviteInstaller(ctx, f.catalog, options, invitation.ReleaseDigest, change.origin, "organization-admin"); !errors.Is(err, change.want) {
				t.Fatal("invalid installer invitation accepted", err)
			}
		})
	}
	var invitations, bindings int
	if err := f.store.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_invitations),(SELECT count(*) FROM uem_desktop_invitation_releases)`).Scan(&invitations, &bindings); err != nil || invitations != 1 || bindings != 1 {
		t.Fatal("failed invitation left orphan registry or binding rows", invitations, bindings, err)
	}
	forged := *request
	forged.DeviceName = "Unbound modified name"
	if _, err := f.store.ClaimInstaller(ctx, f.catalog, forged, "https://uem.example.test"); err == nil {
		t.Fatal("installer binding bypassed endpoint key proof")
	}
	if _, err := f.store.ClaimInstaller(ctx, f.catalog, *request, "https://other.example.test"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatal("claim accepted another configured origin", err)
	}
	issued, err := f.store.ClaimInstaller(ctx, f.catalog, *request, "https://uem.example.test")
	if err != nil || issued.TenantID != 1 || issued.SiteID != 1 || issued.Endpoint != "wss://uem.example.test/agent-channel" {
		t.Fatal("bound installer claim failed", err)
	}
	retry, err := f.store.ClaimInstaller(ctx, f.catalog, *request, "https://uem.example.test")
	if err != nil || retry.DeviceID != issued.DeviceID || retry.Certificate != issued.Certificate {
		t.Fatal("installer claim retry changed identity", err)
	}
	var uses, identities, consumers int
	if err = f.store.db.QueryRow(`SELECT (SELECT uses FROM uem_agent_invitations WHERE id=$1),(SELECT count(*) FROM uem_agent_identities WHERE invitation_id=$1),(SELECT count(*) FROM uem_agent_command_consumers WHERE device_id=$2)`, invitation.ID, issued.DeviceID).Scan(&uses, &identities, &consumers); err != nil || uses != 1 || identities != 1 || consumers != 1 {
		t.Fatal("claim side effects or use count are incorrect", uses, identities, consumers, err)
	}
}

func TestInstallerClaimsRejectUnboundWithdrawnAndSupersededInvitations(t *testing.T) {
	f := newCatalogFixture(t)
	ctx := context.Background()
	invitation, request := prepareInstallerInvitation(t, f)
	legacy, err := f.store.Registry.Invite(ctx, invitation.InvitationOptions, "legacy-test-caller")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	legacyProof, err := keys.Request(legacy.URL[strings.LastIndex(legacy.URL, "/")+1:], "windows", "amd64", "Unbound endpoint")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.ClaimInstaller(ctx, f.catalog, *legacyProof, "https://uem.example.test"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatal("registry-only invitation bypassed installer approval", err)
	}
	if err = f.catalog.Withdraw(ctx, invitation.ReleaseDigest, "server-admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.ClaimInstaller(ctx, f.catalog, *request, "https://uem.example.test"); !errors.Is(err, ErrWithdrawn) {
		t.Fatal("withdrawn release issued a new identity", err)
	}
	m := f.manifest
	m.Sequence++
	data, _, _ := f.prepare(t, m)
	if _, err = f.catalog.Accept(ctx, data, "release-pipeline"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.ClaimInstaller(ctx, f.catalog, *request, "https://uem.example.test"); !errors.Is(err, ErrNoRelease) {
		t.Fatal("superseded invitation selected a different release automatically", err)
	}
	var uses, identities int
	if err = f.store.db.QueryRow(`SELECT (SELECT sum(uses) FROM uem_agent_invitations),(SELECT count(*) FROM uem_agent_identities)`).Scan(&uses, &identities); err != nil || uses != 0 || identities != 0 {
		t.Fatal("denied installer claims changed issuance state", err)
	}
}

func TestReleaseWithdrawalWaitsForAuthorizedInstallerIssuance(t *testing.T) {
	f := newCatalogFixture(t)
	invitation, request := prepareInstallerInvitation(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	blocker, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var work sync.WaitGroup
	defer func() { cancel(); blocker.Rollback(); work.Wait() }()
	var blockerPID int
	if err = blocker.QueryRowContext(ctx, `SELECT pg_backend_pid() FROM uem_agent_invitations WHERE id=$1 FOR UPDATE`, invitation.ID).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	claims := make(chan error, 1)
	work.Go(func() {
		_, err := f.store.ClaimInstaller(ctx, f.catalog, *request, "https://uem.example.test")
		claims <- err
	})
	// The claim first holds the release checkpoint, then waits for this fixture's
	// invitation row lock. Observe real database lock dependencies, not sleeps.
	claimPID := waitForBlockedConnection(t, ctx, f.store.db, blockerPID)
	withdrawals := make(chan error, 1)
	work.Go(func() { withdrawals <- f.catalog.Withdraw(ctx, invitation.ReleaseDigest, "server-admin") })
	_ = waitForBlockedConnection(t, ctx, f.store.db, claimPID)
	if err = blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-claims; err != nil {
		t.Fatal("authorized in-flight issuance failed", err)
	}
	if err = <-withdrawals; err != nil {
		t.Fatal("withdrawal did not finish after issuance", err)
	}
	if _, err = f.store.ClaimInstaller(ctx, f.catalog, *request, "https://uem.example.test"); !errors.Is(err, ErrWithdrawn) {
		t.Fatal("new request bypassed the committed withdrawal", err)
	}
	var count int
	if err = f.store.db.QueryRow(`SELECT count(*) FROM uem_agent_identities WHERE invitation_id=$1 AND revoked_at IS NULL`, invitation.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("release withdrawal unexpectedly revoked the previously issued identity", err)
	}
}

func waitForBlockedConnection(t *testing.T, ctx context.Context, db *sql.DB, blocker int) int {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var pid int
		err := db.QueryRowContext(ctx, `SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) ORDER BY pid LIMIT 1`, blocker).Scan(&pid)
		if err == nil {
			return pid
		}
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("could not observe transaction ordering", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("expected database lock dependency was not observed")
		case <-ticker.C:
		}
	}
}
