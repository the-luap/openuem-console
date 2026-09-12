package oidcaccounts_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/security/oidcaccounts"
)

func TestOIDCAdmissionPreservesValidFirstLoginAndMFAStages(t *testing.T) {
	for _, stage := range []string{"no MFA", "pending enrollment", "confirmed MFA", "new enrollment", "auto approval"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t)
			if err := f.change(t, "admin", "reader", "admission-subject", "link", 0); err != nil {
				t.Fatal(err)
			}
			status := nats.REGISTER_APPROVED
			if stage == "auto approval" {
				settings, err := f.m.GetAuthenticationSettings()
				if err != nil {
					t.Fatal(err)
				}
				if err = settings.Update().SetOIDCAutoApprove(true).Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
				f.p.AutoApprove = true
				status = nats.REGISTER_IN_REVIEW
			}
			u, err := f.m.Client.User.UpdateOneID("reader").SetRegister(status).SetUse2fa(stage != "no MFA" && stage != "auto approval").SetTotpSecretConfirmed(stage == "confirmed MFA").SetTotpSecret("owned stored MFA secret").SetCertClearPassword("owned temporary credential").Save(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			identity, err := f.s.SessionFor(t.Context(), f.p, u.ID, "admission-subject")
			if err != nil {
				t.Fatal(err)
			}
			if stage == "new enrollment" {
				if err = u.Update().SetTotpSecretConfirmed(true).Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if err = f.s.AdmitSession(t.Context(), *identity, u, stage == "confirmed MFA" || stage == "new enrollment"); err != nil {
				t.Fatal("valid OpenID admission failed", err)
			}
			current, err := f.m.Client.User.Get(t.Context(), u.ID)
			if err != nil {
				t.Fatal(err)
			}
			if current.Register != nats.REGISTER_COMPLETE || current.CertClearPassword != "" || current.TotpSecret != u.TotpSecret {
				t.Fatal("confirmation did not preserve valid MFA state")
			}
			if err = f.s.ValidateSession(t.Context(), *identity); err != nil {
				t.Fatal("valid admission did not retain its identity", err)
			}
		})
	}
}

func TestOIDCAdmissionObservesBindingOutcomeAfterLockWait(t *testing.T) {
	for _, outcome := range []string{"commit", "rollback", "cancel"} {
		t.Run(outcome, func(t *testing.T) {
			f := newFixture(t)
			if err := f.change(t, "admin", "reader", "admission-subject", "link", 0); err != nil {
				t.Fatal(err)
			}
			u, err := f.m.Client.User.Get(t.Context(), "reader")
			if err != nil {
				t.Fatal(err)
			}
			identity, err := f.s.SessionFor(t.Context(), f.p, u.ID, "admission-subject")
			if err != nil {
				t.Fatal(err)
			}
			tx, err := f.m.DB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tx.Rollback() })
			if _, err = tx.ExecContext(t.Context(), `SELECT pg_advisory_xact_lock(684627916)`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.ExecContext(t.Context(), `UPDATE uem_oidc_bindings SET active=false WHERE user_id='reader'`); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- f.s.AdmitSession(ctx, *identity, u, false) }()
			deadline := time.Now().Add(4 * time.Second)
			for {
				var waiting bool
				if err = f.m.DB.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query='SELECT pg_advisory_xact_lock_shared(684627916)')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("admission did not wait for the owned binding change")
				}
				time.Sleep(time.Millisecond)
			}
			if outcome == "cancel" {
				cancel()
				if err = <-done; !errors.Is(err, context.Canceled) {
					t.Fatal("admission ignored cancellation", err)
				}
			}
			if outcome == "commit" {
				err = tx.Commit()
			} else {
				err = tx.Rollback()
			}
			if err != nil {
				t.Fatal(err)
			}
			if outcome != "cancel" {
				err = <-done
				if outcome == "commit" && !errors.Is(err, oidcaccounts.ErrIdentity) || outcome == "rollback" && err != nil {
					t.Fatal("admission missed the binding outcome", err)
				}
			}
			current, err := f.m.Client.User.Get(t.Context(), u.ID)
			if err != nil {
				t.Fatal(err)
			}
			status := u.Register
			if outcome == "rollback" {
				status = nats.REGISTER_COMPLETE
			}
			if current.Register != status {
				t.Fatal("denied admission changed registration")
			}
		})
	}
}

func TestOIDCAutoApprovalCannotUndoInterveningReview(t *testing.T) {
	for _, secondFactor := range []bool{false, true} {
		f := newFixture(t)
		if err := f.change(t, "admin", "reader", "admission-subject", "link", 0); err != nil {
			t.Fatal(err)
		}
		settings, err := f.m.GetAuthenticationSettings()
		if err != nil {
			t.Fatal(err)
		}
		if err = settings.Update().SetOIDCAutoApprove(true).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.p.AutoApprove = true
		u, err := f.m.Client.User.UpdateOneID("reader").SetUse2fa(secondFactor).SetTotpSecretConfirmed(secondFactor).SetTotpSecret("owned MFA secret").Save(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		identity, err := f.s.SessionFor(t.Context(), f.p, u.ID, "admission-subject")
		if err != nil {
			t.Fatal(err)
		}
		if err = u.Update().SetRegister(nats.REGISTER_IN_REVIEW).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err = f.s.AdmitSession(t.Context(), *identity, u, secondFactor); !errors.Is(err, oidcaccounts.ErrIdentity) {
			t.Fatal("automatic approval undid intervening review", secondFactor, err)
		}
		current, err := f.m.Client.User.Get(t.Context(), u.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.Register != nats.REGISTER_IN_REVIEW {
			t.Fatal("denied admission changed registration")
		}
	}
}
