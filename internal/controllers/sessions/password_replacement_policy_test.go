package sessions_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/alexedwards/scs/v2"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/models"
)

func TestPasswordReplacementCannotOverrideCurrentPolicy(t *testing.T) {
	for _, kind := range []string{models.PasswordReplacementInitial, models.PasswordReplacementRecovery, models.PasswordReplacementInvitation} {
		for _, policy := range []string{"revoked", "review", "certificate mode", "OpenID mode", "disabled passwords"} {
			t.Run(kind+"/"+policy, func(t *testing.T) {
				f := newSessionFixture(t, true)
				if err := f.model.CreateInitialSettings(); err != nil {
					t.Fatal(err)
				}
				settings, err := f.model.GetAuthenticationSettings()
				if err != nil {
					t.Fatal(err)
				}
				if err = settings.Update().SetUsePasswd(true).Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
				hash, err := argon2id.CreateHash("Owned-Previous-Password-123!", argon2id.DefaultParams)
				if err != nil {
					t.Fatal(err)
				}
				register := nats.REGISTER_COMPLETE
				if kind == models.PasswordReplacementInitial {
					register = nats.REGISTER_FORCE_PASSWORD_CHANGE
				}
				user, err := f.model.Client.User.Create().SetID("replacement-user").SetName("Owned replacement user").SetPasswd(true).SetHash(hash).SetRegister(register).SetForgotPasswordCode("owned-verified-code-hash").SetForgotPasswordCodeExpiresAt(time.Now().Add(time.Hour)).SetNewUserToken("owned-verified-invitation").Save(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				proof := models.PasswordReplacementProof{Kind: kind, PasswordDigest: models.PasswordReplacementDigest(hash), ExpiresAt: time.Now().Add(time.Minute)}
				if kind == models.PasswordReplacementRecovery {
					proof.SourceDigest = models.PasswordReplacementDigest(user.ForgotPasswordCode)
				}
				if kind == models.PasswordReplacementInvitation {
					proof.SourceDigest = models.PasswordReplacementDigest(user.NewUserToken)
				}
				// The first factor was verified before this policy change.
				switch policy {
				case "revoked":
					register = nats.REGISTER_REVOKED
					err = user.Update().SetRegister(register).Exec(t.Context())
				case "review":
					register = nats.REGISTER_IN_REVIEW
					err = user.Update().SetRegister(register).Exec(t.Context())
				case "certificate mode":
					err = user.Update().SetPasswd(false).Exec(t.Context())
				case "OpenID mode":
					err = user.Update().SetOpenid(true).Exec(t.Context())
				case "disabled passwords":
					err = settings.Update().SetUsePasswd(false).Exec(t.Context())
				}
				if err != nil {
					t.Fatal(err)
				}
				sm := scs.New()
				sm.Store = f.store
				ctx, err := sm.Load(t.Context(), "")
				if err != nil {
					t.Fatal(err)
				}
				sm.Put(ctx, "uid", user.ID)
				token, _, err := sm.Commit(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.model.AddUserToSession(t.Context(), token, user.ID, f.key); err != nil {
					t.Fatal(err)
				}
				if err = f.model.ChangePasswordWithProof(t.Context(), user.ID, "Owned-Replacement-Password-456!", proof); err == nil {
					t.Error("earlier password proof ignored current account/method policy")
				}
				current, err := f.model.Client.User.Get(t.Context(), user.ID)
				if err != nil {
					t.Fatal(err)
				}
				if current.Hash != hash || current.Register != register || current.ForgotPasswordCode != user.ForgotPasswordCode || current.NewUserToken != user.NewUserToken {
					t.Error("denied replacement changed credentials or registration")
				}
				if _, found, err := f.store.FindCtx(t.Context(), token); err != nil || !found {
					t.Error("denied replacement removed another session", err)
				}
			})
		}
	}
}

func TestPasswordReplacementRetiresPreloadedSessions(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, kind := range []string{models.PasswordReplacementRecovery, models.PasswordReplacementInvitation} {
			t.Run(sessionMode(encrypted)+"/"+kind, func(t *testing.T) {
				f := newSessionFixture(t, encrypted)
				if err := f.model.CreateInitialSettings(); err != nil {
					t.Fatal(err)
				}
				settings, err := f.model.GetAuthenticationSettings()
				if err != nil {
					t.Fatal(err)
				}
				if err = settings.Update().SetUsePasswd(true).Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
				hash, err := argon2id.CreateHash("Owned-Previous-Password-123!", argon2id.DefaultParams)
				if err != nil {
					t.Fatal(err)
				}
				user, err := f.model.Client.User.Create().SetID("replacement-user").SetName("Owned replacement user").SetPasswd(true).SetHash(hash).SetRegister(nats.REGISTER_COMPLETE).SetUse2fa(true).SetTotpSecretConfirmed(true).SetTotpSecret("owned-preserved-mfa-secret").SetForgotPasswordCode("owned-verified-code-hash").SetForgotPasswordCodeExpiresAt(time.Now().Add(time.Hour)).SetNewUserToken("owned-verified-invitation").Save(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				proof := models.PasswordReplacementProof{Kind: kind, PasswordDigest: models.PasswordReplacementDigest(hash), ExpiresAt: time.Now().Add(time.Minute), SourceDigest: models.PasswordReplacementDigest(user.ForgotPasswordCode)}
				if kind == models.PasswordReplacementInvitation {
					proof.SourceDigest = models.PasswordReplacementDigest(user.NewUserToken)
				}
				sm := scs.New()
				sm.Store = f.store
				ctx, err := sm.Load(t.Context(), "")
				if err != nil {
					t.Fatal(err)
				}
				sm.Put(ctx, "uid", user.ID)
				token, _, err := sm.Commit(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.model.AddUserToSession(t.Context(), token, user.ID, f.key); err != nil {
					t.Fatal(err)
				}
				late, err := sm.Load(t.Context(), token)
				if err != nil {
					t.Fatal(err)
				}
				const replacement = "Owned-Replacement-Password-456!"
				if err = f.model.ChangePasswordWithProof(t.Context(), user.ID, replacement, proof); err != nil {
					t.Fatal("valid replacement failed", err)
				}
				current, err := f.model.Client.User.Get(t.Context(), user.ID)
				if err != nil {
					t.Fatal(err)
				}
				if match, err := argon2id.ComparePasswordAndHash(replacement, current.Hash); err != nil || !match {
					t.Fatal("new password was not retained", err)
				}
				if current.ForgotPasswordCode != "" || current.NewUserToken != "" || !current.Use2fa || !current.TotpSecretConfirmed || current.TotpSecret != user.TotpSecret {
					t.Fatal("replacement failed to consume grants or changed MFA")
				}
				if _, _, err = sm.Commit(late); !errors.Is(err, sessions.ErrRevoked) {
					t.Fatal("replacement allowed a preloaded session to return", err)
				}
				if err = f.model.ChangePasswordWithProof(t.Context(), user.ID, "Replayed-Replacement-Password-789!", proof); !errors.Is(err, models.ErrPasswordReplacement) {
					t.Fatal("old grant could replace the new password", err)
				}
			})
		}
	}
}

func TestPasswordReplacementObservesRevocationAfterRowLock(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed revocation", true: "rolled-back revocation"}[rollback], func(t *testing.T) {
			f := newSessionFixture(t, true)
			if err := f.model.CreateInitialSettings(); err != nil {
				t.Fatal(err)
			}
			settings, err := f.model.GetAuthenticationSettings()
			if err != nil {
				t.Fatal(err)
			}
			if err = settings.Update().SetUsePasswd(true).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			user, err := f.model.Client.User.Create().SetID("replacement-user").SetName("Owned replacement user").SetPasswd(true).SetHash("owned-verified-old-hash").SetRegister(nats.REGISTER_COMPLETE).SetNewUserToken("owned-verified-invitation").Save(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			proof := models.PasswordReplacementProof{Kind: models.PasswordReplacementInvitation, PasswordDigest: models.PasswordReplacementDigest(user.Hash), SourceDigest: models.PasswordReplacementDigest(user.NewUserToken), ExpiresAt: time.Now().Add(time.Minute)}
			tx, err := f.model.DB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = tx.Exec(`UPDATE users SET register=$2 WHERE uid=$1`, user.ID, nats.REGISTER_REVOKED); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- f.model.ChangePasswordWithProof(ctx, user.ID, "Owned-Replacement-Password-456!", proof)
			}()
			deadline := time.Now().Add(time.Second)
			for {
				var waiting bool
				if err = f.model.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT hash,register,forgot_password_code%FOR UPDATE')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("replacement did not wait for the owned account transaction")
				}
				time.Sleep(time.Millisecond)
			}
			if rollback {
				err = tx.Rollback()
			} else {
				err = tx.Commit()
			}
			if err != nil {
				t.Fatal(err)
			}
			err = <-done
			if rollback && err != nil {
				t.Fatal("rolled-back revocation blocked valid replacement", err)
			}
			if !rollback && !errors.Is(err, models.ErrPasswordReplacement) {
				t.Fatal("replacement missed the intervening revocation", err)
			}
			current, err := f.model.Client.User.Get(t.Context(), user.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !rollback && (current.Register != nats.REGISTER_REVOKED || current.Hash != user.Hash) {
				t.Fatal("replacement undid the committed revocation")
			}
		})
	}
}
