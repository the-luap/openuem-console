package oidcaccounts_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/oidcaccounts"
)

func enrollmentCodes() []string {
	codes := make([]string, 10)
	for i := range codes {
		codes[i] = fmt.Sprintf("owned-enrollment-code-%d", i)
	}
	return codes
}

func TestOIDCMFAEnrollmentRejectsInterveningIdentityChanges(t *testing.T) {
	for _, operation := range []string{"stage", "confirm", "disable"} {
		for _, mutation := range []string{"binding revision", "disabled binding", "enabled", "issuer", "client", "provider", "role", "auto create", "auto approve", "restored policy"} {
			t.Run(operation+"/"+mutation, func(t *testing.T) {
				f := newFixture(t)
				if err := f.change(t, "admin", "reader", "enrollment-subject", "link", 0); err != nil {
					t.Fatal(err)
				}
				u, err := f.m.Client.User.UpdateOneID("reader").SetUse2fa(true).SetTotpSecret("JBSWY3DPEHPK3PXP").SetTotpSecretConfirmed(operation == "disable").Save(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				identity, err := f.s.SessionFor(t.Context(), f.p, u.ID, "enrollment-subject")
				if err != nil {
					t.Fatal(err)
				}
				if mutation == "binding revision" || mutation == "disabled binding" {
					if err = f.change(t, "admin", u.ID, identity.Subject, "disable", identity.Revision); err != nil {
						t.Fatal(err)
					}
					if mutation == "binding revision" {
						if err = f.change(t, "admin", u.ID, identity.Subject, "enable", identity.Revision+1); err != nil {
							t.Fatal(err)
						}
					}
				} else {
					statements := map[string]string{
						"enabled":         `UPDATE authentications SET use_oidc=false`,
						"restored policy": `UPDATE authentications SET oidc_role='temporary'; UPDATE authentications SET oidc_role='members'`,
						"issuer":          `UPDATE authentications SET oidc_issuer_url='https://replacement.example.test'`,
						"client":          `UPDATE authentications SET oidc_client_id='replacement-client'`,
						"provider":        `UPDATE authentications SET oidc_provider='keycloak'`,
						"role":            `UPDATE authentications SET oidc_role='replacement-role'`,
						"auto create":     `UPDATE authentications SET oidc_auto_create_account=true`,
						"auto approve":    `UPDATE authentications SET oidc_auto_approve=true`,
					}
					if _, err = f.m.DB.ExecContext(t.Context(), statements[mutation]); err != nil {
						t.Fatal(err)
					}
				}
				switch operation {
				case "stage":
					err = f.m.StageOIDCTOTPSecret(t.Context(), u, "KRSXG5DSNFXGOIDT", oidcaccounts.AccountMFA(*identity))
				case "confirm":
					err = f.m.ConfirmOIDCMFA(t.Context(), u, enrollmentCodes(), oidcaccounts.AccountMFA(*identity))
				case "disable":
					err = f.m.DisableOIDCMFA(t.Context(), u, oidcaccounts.AccountMFA(*identity))
				}
				if !errors.Is(err, models.ErrMFAState) {
					t.Errorf("changed OpenID identity authorized MFA mutation: %v", err)
				}
				current, err := f.m.Client.User.Get(t.Context(), u.ID)
				if err != nil {
					t.Fatal(err)
				}
				var codes int
				if err = f.m.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM recovery_codes WHERE user_recoverycodes=$1`, u.ID).Scan(&codes); err != nil {
					t.Fatal(err)
				}
				if current.Use2fa != u.Use2fa || current.TotpSecret != u.TotpSecret || current.TotpSecretConfirmed != u.TotpSecretConfirmed || codes != 0 {
					t.Error("denied MFA mutation changed enrollment")
				}
			})
		}
	}
}

// Each write waits on a real source lock; committing, rolling back and canceling
// the competing transaction must produce distinct authorization outcomes.
func TestOIDCMFAEnrollmentObservesSourceLockOutcome(t *testing.T) {
	for _, source := range []string{"policy", "binding", "account"} {
		for _, outcome := range []string{"commit", "rollback", "cancel"} {
			t.Run(source+"/"+outcome, func(t *testing.T) {
				f := newFixture(t)
				u, identity := enrollmentIdentity(t, f)
				tx, err := f.m.DB.BeginTx(t.Context(), nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = tx.Rollback() })
				statement := map[string]string{
					"policy":  `UPDATE authentications SET oidc_role='changed-role'`,
					"binding": `UPDATE uem_oidc_bindings SET active=false WHERE user_id='reader'`,
					"account": `UPDATE users SET openid=false WHERE uid='reader'`,
				}[source]
				if _, err = tx.ExecContext(t.Context(), statement); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- f.m.StageOIDCTOTPSecret(ctx, u, "KRSXG5DSNFXGOIDT", oidcaccounts.AccountMFA(identity)) }()
				deadline := time.Now().Add(4 * time.Second)
				for {
					var waiting bool
					if err = f.m.DB.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND pid<>pg_backend_pid() AND query LIKE $1)`, map[string]string{"policy": "%FROM authentications ORDER BY id LIMIT 2 FOR SHARE%", "binding": "%FOR SHARE OF a,b%", "account": "%FROM users WHERE uid=$1 FOR UPDATE%"}[source]).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("MFA write did not wait for its source")
					}
					time.Sleep(time.Millisecond)
				}
				if outcome == "cancel" {
					cancel()
					if err = <-done; !errors.Is(err, context.Canceled) {
						t.Fatal("MFA write ignored cancellation", err)
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
					if outcome == "commit" && !errors.Is(err, models.ErrMFAState) || outcome == "rollback" && err != nil {
						t.Fatal("MFA write missed source outcome", err)
					}
				}
				current, err := f.m.Client.User.Get(t.Context(), u.ID)
				if err != nil {
					t.Fatal(err)
				}
				secret := u.TotpSecret
				if outcome == "rollback" {
					secret = "KRSXG5DSNFXGOIDT"
				}
				if current.TotpSecret != secret {
					t.Fatal("MFA write changed the wrong state")
				}
				if outcome == "cancel" {
					if err = f.m.StageOIDCTOTPSecret(t.Context(), u, "KRSXG5DSNFXGOIDT", oidcaccounts.AccountMFA(identity)); err != nil {
						t.Fatal("canceled mutation prevented a valid retry", err)
					}
				}
			})
		}
	}
}

func enrollmentIdentity(t *testing.T, f fixture) (*ent.User, oidcaccounts.Session) {
	t.Helper()
	if err := f.change(t, "admin", "reader", "enrollment-subject", "link", 0); err != nil {
		t.Fatal(err)
	}
	u, err := f.m.Client.User.UpdateOneID("reader").SetUse2fa(true).SetTotpSecret("JBSWY3DPEHPK3PXP").Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := f.s.SessionFor(t.Context(), f.p, u.ID, "enrollment-subject")
	if err != nil {
		t.Fatal(err)
	}
	return u, *identity
}

func TestOIDCMFAEnrollmentUnavailableIdentityPreservesRetry(t *testing.T) {
	f := newFixture(t)
	u, identity := enrollmentIdentity(t, f)
	authorization := oidcaccounts.AccountMFA(identity)
	if _, err := f.m.DB.ExecContext(t.Context(), `ALTER TABLE uem_oidc_bindings RENAME TO owned_unavailable_bindings`); err != nil {
		t.Fatal(err)
	}
	err := f.m.StageOIDCTOTPSecret(t.Context(), u, "KRSXG5DSNFXGOIDT", authorization)
	if err == nil || errors.Is(err, models.ErrMFAState) {
		t.Fatal("unavailable binding source was accepted or treated as revoked access", err)
	}
	current, err := f.m.Client.User.Get(t.Context(), u.ID)
	if err != nil || current.TotpSecret != u.TotpSecret || current.TotpSecretConfirmed {
		t.Fatal("unavailable identity changed enrollment", err)
	}
	if _, err = f.m.DB.ExecContext(t.Context(), `ALTER TABLE owned_unavailable_bindings RENAME TO uem_oidc_bindings`); err != nil {
		t.Fatal(err)
	}
	if err = f.m.StageOIDCTOTPSecret(t.Context(), u, "KRSXG5DSNFXGOIDT", authorization); err != nil {
		t.Fatal("restored binding source prevented an unchanged authorized retry", err)
	}
}

func TestOIDCMFAEnrollmentRequiresBoundPrimaryEvidence(t *testing.T) {
	for _, invalid := range []string{"missing", "expired", "wrong method", "wrong user", "wrong identity", "zero authorization", "unbound model API", "valid"} {
		t.Run(invalid, func(t *testing.T) {
			f := newFixture(t)
			u, identity := enrollmentIdentity(t, f)
			raw, err := json.Marshal(identity)
			if err != nil {
				t.Fatal(err)
			}
			method, uid, credential, at := loginproof.OpenID, u.ID, string(raw), time.Now()
			switch invalid {
			case "expired":
				at = at.Add(-loginproof.Lifetime)
			case "wrong method":
				method = loginproof.Password
			case "wrong user":
				uid = "other"
			case "wrong identity":
				credential += "changed"
			}
			primary := loginproof.New(uid, method, credential, at)
			if invalid == "missing" {
				primary = ""
			}
			authorization := oidcaccounts.PrimaryMFA(identity, primary)
			if invalid == "zero authorization" {
				authorization = oidcaccounts.MFAAuthorization{}
			}
			if invalid == "unbound model API" {
				err = f.m.SaveTOTPSecretKey(t.Context(), u, "KRSXG5DSNFXGOIDT")
			} else {
				err = f.m.StageOIDCTOTPSecret(t.Context(), u, "KRSXG5DSNFXGOIDT", authorization)
			}
			if invalid == "valid" && err != nil || invalid != "valid" && !errors.Is(err, models.ErrMFAState) {
				t.Fatal("incorrect primary enrollment authorization", err)
			}
			current, err := f.m.Client.User.Get(t.Context(), u.ID)
			if err != nil {
				t.Fatal(err)
			}
			if invalid == "valid" {
				u = current
			}
			if current.TotpSecret != u.TotpSecret {
				t.Fatal("invalid primary altered staged secret")
			}
			if invalid == "unbound model API" {
				err = f.m.SaveRecoveryCodes(t.Context(), u, enrollmentCodes())
			} else {
				err = f.m.ConfirmOIDCMFA(t.Context(), u, enrollmentCodes(), authorization)
			}
			if invalid == "valid" && err != nil || invalid != "valid" && !errors.Is(err, models.ErrMFAState) {
				t.Fatal("incorrect primary confirmation authorization", err)
			}
			current, err = f.m.Client.User.Get(t.Context(), u.ID)
			if err != nil {
				t.Fatal(err)
			}
			var count int
			if err = f.m.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM recovery_codes WHERE user_recoverycodes=$1`, u.ID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if invalid == "valid" {
				if !current.TotpSecretConfirmed || count != 10 {
					t.Fatal("valid primary did not confirm enrollment")
				}
			} else if current.TotpSecretConfirmed || count != 0 {
				t.Fatal("invalid primary confirmed enrollment")
			}
		})
	}
}
