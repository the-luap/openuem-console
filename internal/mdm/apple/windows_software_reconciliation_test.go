package apple

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

type windowsReconciliationFixture struct {
	*windowsDispatchFixture
	original *enrollment.SoftwareTask
	secret   *enrollment.SoftwareSecret
}

func newWindowsReconciliationFixture(t *testing.T) *windowsReconciliationFixture {
	t.Helper()
	f := &windowsReconciliationFixture{windowsDispatchFixture: newWindowsDispatchFixture(t, "windows-msi", "install")}
	review := f.review(t)
	if _, err := f.store.DispatchWindowsSoftware(t.Context(), Scope{TenantID: 1, SiteID: 1}, f.version.ID, f.request.ID, uuid.NewString(), review.ReviewHash, "operator", f.permissions); err != nil {
		t.Fatal(err)
	}
	reply, err := f.call(t, enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID})
	if err != nil || reply.Task == nil {
		t.Fatal(err)
	}
	f.original = reply.Task
	f.secret, err = f.key.Open(*f.original, f.authority, f.recipient.Identity, f.recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.secret.Close)
	nonce := f.secret.Nonce()
	defer clear(nonce)
	outcome := enrollment.SoftwareOutcome{State: "uncertain", Execution: "unknown", Before: enrollment.SoftwareObservation{State: "unknown"}, After: enrollment.SoftwareObservation{State: "unknown"}, Error: "interrupted"}
	result, err := enrollment.SignSoftwareResult(f.original.Context, f.recipient.Identity, f.secret.TaskHash(), nonce, outcome, f.cert, f.keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(result.Nonce)
	proof, err := enrollment.SignSoftwareSubmission(*result, f.recipient.Identity, f.cert, f.keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.call(t, enrollment.SoftwareRequest{Action: "result", Result: result, Submission: proof}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *windowsReconciliationFixture) reviewReconciliation(t *testing.T) *WindowsSoftwareReconciliationReview {
	t.Helper()
	review, err := f.store.ReviewWindowsSoftwareReconciliation(t.Context(), Scope{TenantID: 1, SiteID: 1}, f.version.ID, f.request.ID, "operator", f.permissions)
	if err != nil {
		t.Fatal(err)
	}
	return review
}

func (f *windowsReconciliationFixture) queue(t *testing.T, review *WindowsSoftwareReconciliationReview, id string) (*registry.SoftwareReconciliationStatus, error) {
	t.Helper()
	return f.store.QueueWindowsSoftwareReconciliation(t.Context(), Scope{TenantID: 1, SiteID: 1}, f.version.ID, f.request.ID, id, review.ReviewHash, "operator", review.ExpiresAt, f.permissions)
}

func (f *windowsReconciliationFixture) reconcile(t *testing.T, request enrollment.SoftwareReconciliationRequest) (*enrollment.SoftwareReconciliationReply, error) {
	t.Helper()
	identity, err := f.channel.ActiveIdentity(t.Context(), f.identity.DeviceID)
	if err != nil {
		return nil, err
	}
	tx, err := f.store.db.BeginTx(t.Context(), nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, _, _, err = f.channel.SoftwareIdentity(t.Context(), tx, identity.Scope, identity.ID); err != nil {
		return nil, err
	}
	var locked string
	if err = tx.QueryRowContext(t.Context(), `SELECT oid FROM agents WHERE oid=$1 FOR UPDATE`, identity.ID).Scan(&locked); err != nil {
		return nil, err
	}
	request.Version, request.Protocol, request.AgentID = enrollment.SoftwareReconciliationVersion, enrollment.SoftwareReconciliationProtocol, identity.ID
	reply, err := f.channel.HandleSoftwareReconciliationInTransaction(t.Context(), tx, *identity, request)
	if err != nil {
		return nil, err
	}
	return reply, tx.Commit()
}

func TestWindowsSoftwareReconciliationReviewDispatchAndSeparateEvidence(t *testing.T) {
	for _, state := range []string{"observed", "drifted", "unknown", "waiting_for_boot", "unavailable"} {
		t.Run(state, func(t *testing.T) {
			f := newWindowsReconciliationFixture(t)
			scope := Scope{TenantID: 1, SiteID: 1}
			review := f.reviewReconciliation(t)
			wire, _ := json.Marshal(review)
			if bytes.Contains(wire, []byte("private-")) || bytes.Contains(wire, []byte("https://")) || bytes.Contains(wire, []byte("nonce")) {
				t.Fatal("review exposed private execution data")
			}
			var count int
			if err := f.store.db.QueryRow(`SELECT count(*) FROM uem_agent_software_reconciliations`).Scan(&count); err != nil || count != 0 {
				t.Fatal("GET review dispatched a check", err)
			}
			id := uuid.NewString()
			if _, err := f.queue(t, review, id); err != nil {
				t.Fatal(err)
			}
			if _, err := f.queue(t, review, id); err != nil {
				t.Fatal("exact retry failed", err)
			}
			page, err := f.store.ReadWindowsSoftwareReconciliations(t.Context(), scope, f.version.ID, f.request.ID, "", "reader", f.permissions)
			if err != nil || len(page.Checks) != 1 || page.Checks[0].Status != "pending" || page.Original.Status != "uncertain" {
				t.Fatal("queued history conflated execution and observation", err)
			}
			var originalReceipt []byte
			if err := f.store.db.QueryRow(`SELECT result FROM uem_agent_software_tasks WHERE id=$1`, f.original.Context.TaskID).Scan(&originalReceipt); err != nil {
				t.Fatal(err)
			}
			defer clear(originalReceipt)
			delivery, err := f.reconcile(t, enrollment.SoftwareReconciliationRequest{Action: "poll"})
			if err != nil || delivery.Task == nil || delivery.Task.Context.ID != id || enrollment.VerifySoftwareReconciliationTask(*delivery.Task, f.authority, f.recipient.Identity, time.Now()) != nil {
				t.Fatal("review did not queue its exact signed read-only task", err)
			}
			outcome := enrollment.SoftwareReconciliationOutcome{State: state, Admission: enrollment.SoftwareBootSession{Sequence: 21, SystemProcessCreated: 133000000000000000}, Current: enrollment.SoftwareBootSession{Sequence: 22, SystemProcessCreated: 133000000000000001}, Observation: enrollment.SoftwareObservation{State: "unknown"}}
			nonce := f.secret.Nonce()
			defer clear(nonce)
			switch state {
			case "observed":
				outcome.Observation = enrollment.SoftwareObservation{State: "present", Version: "1.2.3"}
			case "drifted":
				outcome.Observation = enrollment.SoftwareObservation{State: "absent"}
			case "waiting_for_boot":
				outcome.Current = outcome.Admission
			case "unavailable":
				outcome.Admission, outcome.Current = enrollment.SoftwareBootSession{}, enrollment.SoftwareBootSession{}
				nonce = nil
			}
			hash, _ := delivery.Task.Digest()
			result, err := enrollment.SignSoftwareReconciliationResult(delivery.Task.Context, hash, nonce, outcome, f.cert, f.keys.Certificate, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer clear(result.OriginalNonce)
			proof, err := enrollment.SignSoftwareReconciliationSubmission(*result, f.recipient.Identity, f.cert, f.keys.Certificate, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.reconcile(t, enrollment.SoftwareReconciliationRequest{Action: "result", Result: result, Submission: proof}); err != nil {
				t.Fatal(err)
			}
			page, err = f.store.ReadWindowsSoftwareReconciliations(t.Context(), scope, f.version.ID, f.request.ID, "", "reader", f.permissions)
			definite := state == "observed" || state == "drifted"
			if err != nil || len(page.Checks) != 1 || page.Checks[0].Outcome == nil || page.Checks[0].Outcome.State != state || page.Checks[0].ReleasesReservation != definite || page.Original.Outcome.State != "uncertain" || (page.Original.ReconciliationID == id) != definite {
				t.Fatal("verified history changed original outcome or release", err)
			}
			var retained []byte
			if err = f.store.db.QueryRow(`SELECT result FROM uem_agent_software_tasks WHERE id=$1`, f.original.Context.TaskID).Scan(&retained); err != nil || !bytes.Equal(originalReceipt, retained) {
				t.Fatal("observation rewrote execution receipt", err)
			}
			clear(retained)
			next, err := f.store.PrepareWindowsSoftware(t.Context(), scope, uuid.NewString(), f.version.ID, f.identity.DeviceID, "install", "operator", f.permissions)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.store.ReviewWindowsSoftwareDispatch(t.Context(), scope, f.version.ID, next.ID, "operator", f.permissions)
			if (err == nil) != definite {
				t.Fatal("console executable reservation ignored authenticated reconciliation", err)
			}
		})
	}
}

func TestWindowsSoftwareReconciliationConcurrentReviewsAndRetries(t *testing.T) {
	for _, exact := range []bool{false, true} {
		t.Run(map[bool]string{false: "competing", true: "exact"}[exact], func(t *testing.T) {
			f := newWindowsReconciliationFixture(t)
			review, id := f.reviewReconciliation(t), uuid.NewString()
			results := make(chan error, 6)
			var work sync.WaitGroup
			for range 6 {
				work.Go(func() {
					current := id
					if !exact {
						current = uuid.NewString()
					}
					_, err := f.queue(t, review, current)
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
			want := 1
			if exact {
				want = 6
			}
			var tasks, reviews, audits int
			if err := f.store.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_software_reconciliations),(SELECT count(*) FROM uem_windows_software_reconciliations),(SELECT count(*) FROM mdm_apple_audit WHERE action='software.windows.reconciliation.queue')`).Scan(&tasks, &reviews, &audits); err != nil || winners != want || tasks != 1 || reviews != 1 || audits != 1 {
				t.Fatal("concurrent confirmation duplicated read-only work", winners, tasks, reviews, audits, err)
			}
		})
	}
}

func TestWindowsSoftwareReconciliationRejectsStaleReviewAndMutableScope(t *testing.T) {
	for _, change := range []string{"disabled", "missing_site", "moved_site", "ambiguous_site", "revoked", "certificate", "rights", "foreign_scope", "other_actor", "deadline", "review_hash"} {
		t.Run(change, func(t *testing.T) {
			f := newWindowsReconciliationFixture(t)
			review := f.reviewReconciliation(t)
			scope, actor := Scope{TenantID: 1, SiteID: 1}, "operator"
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
			case "certificate":
				_, err = f.store.db.Exec(`UPDATE uem_agent_identities SET certificate_hash=$1`, strings.Repeat("b", 64))
			case "rights":
				err = f.permissions.ReplaceGrants(t.Context(), "admin", "operator", 1, nil)
			case "foreign_scope":
				scope.SiteID = 3
			case "other_actor":
				actor = "admin"
			case "deadline":
				review.ExpiresAt = review.ExpiresAt.Add(time.Minute)
			case "review_hash":
				review.ReviewHash = strings.Repeat("a", 64)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.QueueWindowsSoftwareReconciliation(t.Context(), scope, f.version.ID, f.request.ID, uuid.NewString(), review.ReviewHash, actor, review.ExpiresAt, f.permissions); err == nil {
				t.Fatal("stale review admitted a read-only task")
			}
			var count int
			if err = f.store.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_software_reconciliations)+(SELECT count(*) FROM uem_windows_software_reconciliations)`).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed review left partial intent", err)
			}
		})
	}
}

func TestWindowsSoftwareReconciliationAuditAndFinalAuthorityRollback(t *testing.T) {
	for _, failure := range []string{"registry_audit", "console_audit", "final_expiry", "review_audit"} {
		t.Run(failure, func(t *testing.T) {
			f := newWindowsReconciliationFixture(t)
			review := f.reviewReconciliation(t)
			action, table := "software.windows.reconciliation.queue", "mdm_apple_audit"
			if failure == "registry_audit" {
				action, table = "software.reconciliation.queued", "uem_agent_audit"
			}
			if failure == "review_audit" {
				action = "software.windows.reconciliation.review"
			}
			body := `RAISE EXCEPTION 'owned reconciliation audit failure';`
			if failure == "final_expiry" {
				body = `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second';`
			}
			if _, err := f.store.db.Exec(`CREATE FUNCTION fail_owned_check() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='` + action + `' THEN ` + body + ` END IF; RETURN NEW; END $$;CREATE TRIGGER fail_owned_check BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION fail_owned_check()`); err != nil {
				t.Fatal(err)
			}
			if failure == "review_audit" {
				if value, err := f.store.ReviewWindowsSoftwareReconciliation(t.Context(), Scope{TenantID: 1, SiteID: 1}, f.version.ID, f.request.ID, "operator", f.permissions); err == nil || value != nil {
					t.Fatal("failed read audit returned review")
				}
			} else if _, err := f.queue(t, review, uuid.NewString()); err == nil {
				t.Fatal("failed audit or authority committed a check")
			}
			var count int
			if err := f.store.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_software_reconciliations)+(SELECT count(*) FROM uem_windows_software_reconciliations)`).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed audit retained partial review or task", err)
			}
		})
	}
}

func TestWindowsSoftwareReconciliationWithdrawnRevisionAndHistoricalCancellation(t *testing.T) {
	f := newWindowsReconciliationFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	if err := f.store.WithdrawSoftwareVersion(t.Context(), Scope{TenantID: 1}, f.version.ID, "admin", f.permissions); err != nil {
		t.Fatal(err)
	}
	review, id := f.reviewReconciliation(t), uuid.NewString()
	if _, err := f.queue(t, review, id); err != nil {
		t.Fatal("withdrawn revision could not be checked", err)
	}
	if _, err := f.store.db.Exec(`UPDATE site_agents SET site_id=3`); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CancelWindowsSoftwareReconciliation(t.Context(), scope, f.version.ID, f.request.ID, id, "reader", f.permissions); err == nil {
		t.Fatal("reader cancelled a check")
	}
	for range 2 {
		if err := f.store.CancelWindowsSoftwareReconciliation(t.Context(), scope, f.version.ID, f.request.ID, id, "operator", f.permissions); err != nil {
			t.Fatal("original site could not cancel pending read", err)
		}
	}
	if err := f.store.agentRegistry.RevokeIdentity(t.Context(), registry.Scope{TenantID: 1, SiteID: 1}, f.identity.DeviceID, "admin"); err != nil {
		t.Fatal(err)
	}
	if status, err := f.queue(t, review, id); err != nil || status.Status != "cancelled" {
		t.Fatal("historical exact retry re-admitted or lost cancelled work", err)
	}
	page, err := f.store.ReadWindowsSoftwareReconciliations(t.Context(), scope, f.version.ID, f.request.ID, "", "reader", f.permissions)
	if err != nil || len(page.Checks) != 1 || page.Checks[0].Status != "cancelled" || page.Checks[0].ReleasesReservation || page.HasActive {
		t.Fatal("withdrawal/move/revocation erased original history", err)
	}
	if _, err := f.store.ReadWindowsSoftwareReconciliations(t.Context(), Scope{TenantID: 1, SiteID: 3}, f.version.ID, f.request.ID, "", "admin", f.permissions); err == nil {
		t.Fatal("moved site acquired original history")
	}
	for _, query := range []string{`DELETE FROM uem_windows_software_reconciliations`, `TRUNCATE uem_windows_software_reconciliations`, `UPDATE uem_windows_software_reconciliations SET review_hash=repeat('b',64)`} {
		if _, err := f.store.db.Exec(query); err == nil {
			t.Fatal("immutable console review history changed")
		}
	}
	var audits int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE resource_id=$1 AND action='software.reconciliation.cancelled'`, id).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("cancel retry duplicated audit", err)
	}
	if _, err := f.store.db.Exec(`CREATE FUNCTION fail_owned_check_read() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='software.windows.reconciliation.read' THEN RAISE EXCEPTION 'owned read audit failure'; END IF; RETURN NEW; END $$;CREATE TRIGGER fail_owned_check_read BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION fail_owned_check_read()`); err != nil {
		t.Fatal(err)
	}
	if value, err := f.store.ReadWindowsSoftwareReconciliations(t.Context(), scope, f.version.ID, f.request.ID, "", "reader", f.permissions); err == nil || value != nil {
		t.Fatal("failed audit exposed check history")
	}
}

func TestWindowsSoftwareReconciliationHistoryIsBoundedAndCursorScoped(t *testing.T) {
	f := newWindowsReconciliationFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	for range 53 {
		review, id := f.reviewReconciliation(t), uuid.NewString()
		if _, err := f.queue(t, review, id); err != nil {
			t.Fatal(err)
		}
		if err := f.store.CancelWindowsSoftwareReconciliation(t.Context(), scope, f.version.ID, f.request.ID, id, "operator", f.permissions); err != nil {
			t.Fatal(err)
		}
	}
	page, err := f.store.ReadWindowsSoftwareReconciliations(t.Context(), scope, f.version.ID, f.request.ID, "", "reader", f.permissions)
	if err != nil || len(page.Checks) != 50 || page.Next == "" {
		t.Fatal("unbounded or incomplete reconciliation history", err)
	}
	older, err := f.store.ReadWindowsSoftwareReconciliations(t.Context(), scope, f.version.ID, f.request.ID, page.Next, "reader", f.permissions)
	if err != nil || len(older.Checks) != 3 || older.Next != "" {
		t.Fatal("reconciliation cursor skipped or repeated history", err)
	}
	seen := make(map[string]bool)
	for _, check := range append(page.Checks, older.Checks...) {
		if seen[check.ID] {
			t.Fatal("cursor repeated a check")
		}
		seen[check.ID] = true
	}
	if page, err := f.store.ReadWindowsSoftwareReconciliations(t.Context(), scope, f.version.ID, f.request.ID, uuid.NewString(), "reader", f.permissions); err != nil || len(page.Checks) != 0 {
		t.Fatal("foreign cursor revealed check history", err)
	}
}
