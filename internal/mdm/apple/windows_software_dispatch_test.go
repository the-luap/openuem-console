package apple

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type windowsDispatchFixture struct {
	store           *Store
	permissions     *access.Store
	version         *SoftwareVersion
	identity        *enrollment.Response
	keys            *enrollment.Keys
	channel         *registry.AccessStore
	cert, authority *x509.Certificate
	key             *enrollment.SoftwareRecipientKey
	recipient       *enrollment.SoftwareRecipient
	request         *WindowsSoftwareRequest
}

func TestWindowsSoftwareDispatchMigrationLeavesExistingPreparationInert(t *testing.T) {
	s, p, v, identity, _ := windowsRequestFixtureBeforeMigration(t, "migrations/039_windows_software_dispatch.sql")
	r, err := s.PrepareWindowsSoftware(t.Context(), Scope{TenantID: 1, SiteID: 1}, uuid.NewString(), v.ID, identity.DeviceID, "install", "operator", p)
	if err != nil {
		t.Fatal(err)
	}
	var original []byte
	if err = s.db.QueryRow(`SELECT row_to_json(r) FROM uem_windows_software_requests r WHERE id=$1`, r.ID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	var current []byte
	var count int
	if err = s.db.QueryRow(`SELECT row_to_json(r),(SELECT count(*) FROM uem_windows_software_dispatches)+(SELECT count(*) FROM uem_agent_software_tasks) FROM uem_windows_software_requests r WHERE id=$1`, r.ID).Scan(&current, &count); err != nil || !bytes.Equal(original, current) || count != 0 {
		t.Fatal("migration changed existing intent or admitted execution", count, err)
	}
	if _, err = s.db.Exec(`UPDATE uem_windows_software_requests SET status='dispatched',completed_at=clock_timestamp() WHERE id=$1`, r.ID); err == nil {
		t.Fatal("preparation promoted without explicit dispatch")
	}
}

func TestWindowsSoftwareExecutablePlanRejectsUnresolvedAndNoncanonicalDefinitions(t *testing.T) {
	for _, kind := range []string{"windows-winget", "windows-msi", "windows-exe", "windows-burn"} {
		input := testWindowsSoftware(kind)
		data, err := input.canonical()
		if err != nil {
			t.Fatal(err)
		}
		for _, operation := range []string{"install", "remove"} {
			if _, err = windowsExecutablePlan(data, operation); (err == nil) != (kind != "windows-winget") {
				t.Fatal("unsupported plan admitted or approved plan rejected", kind, operation, err)
			}
			for _, bad := range [][]byte{append([]byte(" "), data...), bytes.Replace(data, []byte(`"input"`), []byte(`"Input"`), 1), append(append([]byte(nil), data[:len(data)-1]...), []byte(`,"extra":true}`)...)} {
				if _, err = windowsExecutablePlan(bad, operation); err == nil {
					t.Fatal("noncanonical executable definition accepted")
				}
			}
		}
		if _, err = windowsExecutablePlan(data, "execute"); err == nil {
			t.Fatal("arbitrary operation accepted")
		}
		input.Architecture = "x86"
		data, err = input.canonical()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = windowsExecutablePlan(data, "install"); err == nil {
			t.Fatal("unsupported native architecture admitted")
		}
	}
}

func TestWindowsSoftwareDispatchCompetingReviewsProduceOneTask(t *testing.T) {
	f := newWindowsDispatchFixture(t, "windows-msi", "install")
	review := f.review(t)
	var work sync.WaitGroup
	results := make(chan error, 6)
	for range 6 {
		work.Go(func() {
			_, err := f.store.DispatchWindowsSoftware(t.Context(), Scope{TenantID: 1, SiteID: 1}, f.version.ID, f.request.ID, uuid.NewString(), review.ReviewHash, "operator", f.permissions)
			results <- err
		})
	}
	work.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	var tasks, dispatches int
	if err := f.store.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_software_tasks),(SELECT count(*) FROM uem_windows_software_dispatches)`).Scan(&tasks, &dispatches); err != nil || winners != 1 || tasks != 1 || dispatches != 1 {
		t.Fatal("competing reviews admitted duplicate work", winners, tasks, dispatches, err)
	}
}

func newWindowsDispatchFixture(t *testing.T, kind, operation string) *windowsDispatchFixture {
	t.Helper()
	s, p, v, identity, keys := windowsRequestFixtureWithKeys(t)
	if kind != "windows-msi" {
		input := testWindowsSoftware(kind)
		input.Identifier = "Vendor.Executable"
		var err error
		v, err = s.PublishWindowsSoftware(t.Context(), Scope{TenantID: 1}, uuid.NewString(), input, "admin", p)
		if err != nil {
			t.Fatal(err)
		}
	}
	channel, err := registry.NewAccessStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	parse := func(text string) *x509.Certificate {
		block, _ := pem.Decode([]byte(text))
		if block == nil {
			t.Fatal("fixture certificate missing")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	key, err := enrollment.NewSoftwareRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Close)
	f := &windowsDispatchFixture{store: s, permissions: p, version: v, identity: identity, keys: keys, channel: channel, cert: parse(identity.Certificate), authority: parse(identity.Authority), key: key}
	reply, err := f.call(t, enrollment.SoftwareRequest{Action: "challenge", PublicKey: key.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := enrollment.SignSoftwareRegistration(*reply.Registration, f.cert, keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	reply, err = f.call(t, enrollment.SoftwareRequest{Action: "register", Registration: reply.Registration, Signature: signature})
	if err != nil {
		t.Fatal(err)
	}
	f.recipient = reply.Recipient
	f.request, err = s.PrepareWindowsSoftware(t.Context(), Scope{TenantID: 1, SiteID: 1}, uuid.NewString(), v.ID, identity.DeviceID, operation, "operator", p)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *windowsDispatchFixture) call(t *testing.T, request enrollment.SoftwareRequest) (*enrollment.SoftwareReply, error) {
	t.Helper()
	ctx := t.Context()
	identity, err := f.channel.ActiveIdentity(ctx, f.identity.DeviceID)
	if err != nil {
		return nil, err
	}
	tx, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, _, _, err = f.channel.SoftwareIdentity(ctx, tx, identity.Scope, identity.ID); err != nil {
		return nil, err
	}
	var locked string
	if err = tx.QueryRowContext(ctx, `SELECT oid FROM agents WHERE oid=$1 FOR UPDATE`, identity.ID).Scan(&locked); err != nil {
		return nil, err
	}
	request.Version, request.Protocol, request.AgentID = enrollment.SoftwareVersion, enrollment.SoftwareProtocol, identity.ID
	reply, err := f.channel.HandleSoftwareInTransaction(ctx, tx, *identity, request)
	if err != nil {
		return nil, err
	}
	return reply, tx.Commit()
}

func (f *windowsDispatchFixture) review(t *testing.T) *WindowsSoftwareDispatchReview {
	t.Helper()
	review, err := f.store.ReviewWindowsSoftwareDispatch(t.Context(), Scope{TenantID: 1, SiteID: 1}, f.version.ID, f.request.ID, "operator", f.permissions)
	if err != nil {
		t.Fatal(err)
	}
	return review
}

func (f *windowsDispatchFixture) assertNoDispatch(t *testing.T) {
	t.Helper()
	var tasks, dispatches int
	var state string
	if err := f.store.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_software_tasks),(SELECT count(*) FROM uem_windows_software_dispatches),status FROM uem_windows_software_requests WHERE id=$1`, f.request.ID).Scan(&tasks, &dispatches, &state); err != nil || tasks != 0 || dispatches != 0 || state != "prepared" {
		t.Fatal("rejected dispatch changed durable state", tasks, dispatches, state, err)
	}
}

func TestWindowsSoftwareDispatchExactPlanAndDurableOutcome(t *testing.T) {
	for _, kind := range []string{"windows-msi", "windows-exe"} {
		for _, operation := range []string{"install", "remove"} {
			t.Run(kind+"_"+operation, func(t *testing.T) {
				f := newWindowsDispatchFixture(t, kind, operation)
				scope := Scope{TenantID: 1, SiteID: 1}
				review := f.review(t)
				f.assertNoDispatch(t)
				wire, _ := json.Marshal(review)
				if bytes.Contains(wire, []byte("private-")) || bytes.Contains(wire, []byte("https://")) {
					t.Fatal("private execution intent exposed in review")
				}
				if _, err := f.store.ReviewWindowsSoftwareDispatch(t.Context(), scope, f.version.ID, f.request.ID, "reader", f.permissions); err == nil {
					t.Fatal("reader reviewed execution")
				}
				id := uuid.NewString()
				if _, err := f.store.DispatchWindowsSoftware(t.Context(), scope, f.version.ID, f.request.ID, id, strings.Repeat("a", 64), "operator", f.permissions); err == nil {
					t.Fatal("missing exact fresh review admitted")
				}
				f.assertNoDispatch(t)
				var wg sync.WaitGroup
				errs := make(chan error, 6)
				for range 6 {
					wg.Go(func() {
						_, err := f.store.DispatchWindowsSoftware(t.Context(), scope, f.version.ID, f.request.ID, id, review.ReviewHash, "operator", f.permissions)
						errs <- err
					})
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					if err != nil {
						t.Fatal("concurrent exact dispatch retry", err)
					}
				}
				var count int
				if err := f.store.db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE resource_id=$1 AND action='software.task.queued'`, id).Scan(&count); err != nil || count != 1 {
					t.Fatal("retry duplicated executable task", count, err)
				}
				if err := f.store.CancelWindowsSoftwarePreparation(t.Context(), scope, f.version.ID, f.request.ID, "operator", f.permissions); err == nil {
					t.Fatal("dispatched preparation became unsent")
				}
				reply, err := f.call(t, enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID})
				if err != nil || reply.Task == nil {
					t.Fatal("explicit dispatch was not deliverable", err)
				}
				secret, err := f.key.Open(*reply.Task, f.authority, f.recipient.Identity, f.recipient.ID, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				defer secret.Close()
				input := testWindowsSoftware(kind)
				if kind == "windows-exe" {
					input.Identifier = "Vendor.Executable"
				}
				definition, _ := input.canonical()
				defer clear(definition)
				want, err := windowsExecutablePlan(definition, operation)
				if err != nil {
					t.Fatal(err)
				}
				expected, _ := want.Digest()
				actual, _ := secret.Plan.Digest()
				if actual != expected || reply.Task.Context.PreparationID != f.request.ID || reply.Task.Context.RevisionID != f.version.ID || reply.Task.Context.ExpiresAt != review.ExpiresAt.Unix() {
					t.Fatal("dispatch changed exact approved operation or deadline")
				}
				if err = f.store.CancelWindowsSoftwareDispatch(t.Context(), scope, f.version.ID, f.request.ID, "operator", f.permissions); err == nil {
					t.Fatal("delivered operation cancelled")
				}
				zero := uint32(0)
				before, after := enrollment.SoftwareObservation{State: "absent"}, enrollment.SoftwareObservation{State: "present", Version: "1.2.3"}
				if operation == "remove" {
					before, after = after, before
				}
				result, err := enrollment.SignSoftwareResult(reply.Task.Context, f.recipient.Identity, secret.TaskHash(), secret.Nonce(), enrollment.SoftwareOutcome{State: "observed", Execution: "started", ExitCode: &zero, Before: before, After: after}, f.cert, f.keys.Certificate, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				proof, err := enrollment.SignSoftwareSubmission(*result, f.recipient.Identity, f.cert, f.keys.Certificate, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.call(t, enrollment.SoftwareRequest{Action: "result", Result: result, Submission: proof}); err != nil {
					t.Fatal(err)
				}
				page, err := f.store.ReadWindowsSoftwareRequests(t.Context(), scope, f.version.ID, "", "", "", "reader", f.permissions)
				if err != nil || len(page.Requests) != 1 || page.Requests[0].Status != "dispatched" || page.Requests[0].Dispatch == nil || page.Requests[0].Dispatch.Outcome == nil || page.Requests[0].Dispatch.Outcome.State != "observed" {
					t.Fatal("scoped observed history missing", err)
				}
				wire, _ = json.Marshal(page)
				if bytes.Contains(wire, []byte("private-")) || bytes.Contains(wire, []byte("Nonce")) {
					t.Fatal("private task material entered request history")
				}
				if err = f.store.agentRegistry.RevokeIdentity(t.Context(), registry.Scope{TenantID: 1, SiteID: 1}, f.identity.DeviceID, "admin"); err != nil {
					t.Fatal(err)
				}
				status, err := f.store.DispatchWindowsSoftware(t.Context(), scope, f.version.ID, f.request.ID, id, review.ReviewHash, "operator", f.permissions)
				if err != nil || status.Status != "reported" {
					t.Fatal("exact terminal retry resurrected or lost historical authority", status, err)
				}
			})
		}
	}
}

func TestWindowsSoftwareDispatchRechecksEveryMutableBoundary(t *testing.T) {
	for _, change := range []string{"disabled", "missing_site", "moved_site", "ambiguous_site", "revoked", "recipient", "certificate", "withdrawn", "rights", "cancelled", "foreign_scope", "other_actor"} {
		t.Run(change, func(t *testing.T) {
			f := newWindowsDispatchFixture(t, "windows-msi", "install")
			review := f.review(t)
			scope := Scope{TenantID: 1, SiteID: 1}
			actor := "operator"
			var err error
			switch change {
			case "disabled":
				_, err = f.store.db.Exec(`UPDATE agents SET agent_status='Disabled'`)
			case "missing_site":
				_, err = f.store.db.Exec(`DELETE FROM site_agents`)
			case "moved_site":
				_, err = f.store.db.Exec(`UPDATE site_agents SET site_id=3`)
			case "ambiguous_site":
				_, err = f.store.db.Exec(`INSERT INTO site_agents VALUES($1,3)`, f.identity.DeviceID)
			case "revoked":
				err = f.store.agentRegistry.RevokeIdentity(t.Context(), registry.Scope{TenantID: 1, SiteID: 1}, f.identity.DeviceID, "admin")
			case "recipient":
				_, err = f.store.db.Exec(`UPDATE uem_agent_software_recipients SET id=$1`, uuid.NewString())
			case "certificate":
				_, err = f.store.db.Exec(`UPDATE uem_agent_identities SET certificate_hash=$1`, strings.Repeat("b", 64))
			case "withdrawn":
				err = f.store.WithdrawSoftwareVersion(t.Context(), Scope{TenantID: 1}, f.version.ID, "admin", f.permissions)
			case "rights":
				err = f.permissions.ReplaceGrants(t.Context(), "admin", "operator", 1, nil)
			case "cancelled":
				err = f.store.CancelWindowsSoftwarePreparation(t.Context(), scope, f.version.ID, f.request.ID, actor, f.permissions)
			case "foreign_scope":
				scope.SiteID = 3
			case "other_actor":
				actor = "admin"
			}
			if err != nil {
				t.Fatal("owned boundary mutation failed", err)
			}
			if _, err = f.store.DispatchWindowsSoftware(t.Context(), scope, f.version.ID, f.request.ID, uuid.NewString(), review.ReviewHash, actor, f.permissions); err == nil {
				t.Fatal("stale review admitted execution", change)
			}
			if change != "cancelled" {
				f.assertNoDispatch(t)
			}
		})
	}
}

func TestWindowsSoftwareDispatchAuditAndFinalExpiryRollback(t *testing.T) {
	for _, failure := range []string{"registry_audit", "console_audit", "final_expiry"} {
		t.Run(failure, func(t *testing.T) {
			f := newWindowsDispatchFixture(t, "windows-msi", "install")
			review := f.review(t)
			query := `CREATE FUNCTION fail_windows_dispatch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='software.windows.dispatch.queue' THEN RAISE EXCEPTION 'owned dispatch audit failure'; END IF; RETURN NEW; END $$;CREATE TRIGGER fail_windows_dispatch BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION fail_windows_dispatch()`
			if failure == "registry_audit" {
				query = strings.ReplaceAll(strings.ReplaceAll(query, "software.windows.dispatch.queue", "software.task.queued"), "mdm_apple_audit", "uem_agent_audit")
			}
			if failure == "final_expiry" {
				query = `CREATE FUNCTION fail_windows_dispatch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='software.windows.dispatch.queue' THEN UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second'; END IF; RETURN NEW; END $$;CREATE TRIGGER fail_windows_dispatch BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION fail_windows_dispatch()`
			}
			if _, err := f.store.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.DispatchWindowsSoftware(context.Background(), Scope{TenantID: 1, SiteID: 1}, f.version.ID, f.request.ID, uuid.NewString(), review.ReviewHash, "operator", f.permissions); err == nil {
				t.Fatal("failed final authority or audit committed dispatch")
			}
			f.assertNoDispatch(t)
		})
	}
}

func TestWindowsSoftwareDispatchCancellationAndImmutableHistory(t *testing.T) {
	f := newWindowsDispatchFixture(t, "windows-msi", "install")
	review := f.review(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	id := uuid.NewString()
	if _, err := f.store.DispatchWindowsSoftware(t.Context(), scope, f.version.ID, f.request.ID, id, review.ReviewHash, "operator", f.permissions); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CancelWindowsSoftwareDispatch(t.Context(), scope, f.version.ID, f.request.ID, "reader", f.permissions); err == nil {
		t.Fatal("reader cancelled executable work")
	}
	if _, err := f.store.db.Exec(`UPDATE site_agents SET site_id=3`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := f.store.CancelWindowsSoftwareDispatch(t.Context(), scope, f.version.ID, f.request.ID, "operator", f.permissions); err != nil {
			t.Fatal("original scope could not cancel undelivered task", err)
		}
	}
	reply, err := f.call(t, enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID})
	if err != nil || reply.Task != nil {
		t.Fatal("cancelled task remained deliverable", err)
	}
	page, err := f.store.ReadWindowsSoftwareRequests(t.Context(), scope, f.version.ID, "", "", "", "reader", f.permissions)
	if err != nil || page.Requests[0].Dispatch.Status != "cancelled" {
		t.Fatal("cancelled history not retained in original scope", err)
	}
	for _, statement := range []string{`DELETE FROM uem_windows_software_dispatches`, `TRUNCATE uem_windows_software_dispatches`, `UPDATE uem_windows_software_dispatches SET review_hash=repeat('b',64)`, `UPDATE uem_windows_software_requests SET status='prepared',completed_at=NULL WHERE status='dispatched'`, `UPDATE uem_windows_software_requests SET status='cancelled' WHERE status='dispatched'`} {
		if _, err = f.store.db.Exec(statement); err == nil {
			t.Fatal("immutable dispatch/preparation history changed", statement)
		}
	}
}
