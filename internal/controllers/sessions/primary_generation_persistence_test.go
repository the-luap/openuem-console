package sessions_test

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/sessiongeneration"
)

func TestPrimaryGenerationPreservesRequiredMFAEnrollment(t *testing.T) {
	f, _ := prepareLocalSession(t, true, true, false)
	u, err := f.user.Update().SetUse2fa(true).SetTotpSecretConfirmed(false).Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	raw := ownedLocalPrimary(t, f.model, u, nil, time.Now())
	proof, err := loginproof.Read(raw, u.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := sessiongeneration.Current(t.Context(), f.model.DB, u.ID, loginproof.Password)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.model.SaveTOTPSecretKey(t.Context(), u, "KRSXG5DSNFXGOIDT"); err != nil {
		t.Fatal(err)
	}
	u, err = f.model.Client.User.Get(t.Context(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.model.SaveRecoveryCodes(t.Context(), u, ownedRecoveryCodes()); err != nil {
		t.Fatal(err)
	}
	u, err = f.model.Client.User.Get(t.Context(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.model.DB.ExecContext(t.Context(), `UPDATE users SET name='Owned updated profile',email='updated@example.test' WHERE uid='owner'; UPDATE authentications SET use_certificates=false`); err != nil {
		t.Fatal(err)
	}
	if err = f.store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	primary, err := sessiongeneration.CurrentPrimary(t.Context(), f.model.DB, u.ID, loginproof.Password)
	if err != nil || primary.Encode() != proof.Generation {
		t.Fatal("normal enrollment, profile changes or restart replaced the primary generation", err)
	}
	current, err := sessiongeneration.Current(t.Context(), f.model.DB, u.ID, loginproof.Password)
	if err != nil || current.Account == completed.Account {
		t.Fatal("MFA confirmation failed to retire the preceding completed generation", err)
	}
	if err = f.model.CheckLocalPrimary(t.Context(), u, loginproof.Password, nil, proof.Generation); err != nil {
		t.Fatal("normal required MFA confirmation invalidated its primary proof", err)
	}
	if err = f.model.CheckLocalPrimary(t.Context(), u, loginproof.Password, nil, current.Encode()); !errors.Is(err, models.ErrLocalSignIn) {
		t.Fatal("completed generation could replace primary proof", err)
	}
}

func TestPrimaryGenerationProtectsEnrollmentWrites(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, action := range []string{"stage", "confirm"} {
			t.Run(sessionMode(encrypted)+"/"+action, func(t *testing.T) {
				f, _ := prepareLocalSession(t, true, encrypted, false)
				u, err := f.user.Update().SetUse2fa(true).SetTotpSecretConfirmed(false).Save(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				raw := ownedLocalPrimary(t, f.model, u, nil, time.Now())
				proof, err := loginproof.Read(raw, u.ID, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if err = f.model.CheckLocalPrimary(t.Context(), u, loginproof.Password, nil, proof.Generation); err != nil {
					t.Fatal(err)
				}
				if _, err = f.model.DB.ExecContext(t.Context(), `UPDATE authentications SET use_passwd=false; UPDATE authentications SET use_passwd=true`); err != nil {
					t.Fatal(err)
				}
				primary := models.LocalMFAAuthorization{Proof: raw}
				if action == "stage" {
					err = f.model.StagePrimaryTOTPSecret(t.Context(), u, "KRSXG5DSNFXGOIDT", primary)
				} else {
					err = f.model.ConfirmPrimaryMFA(t.Context(), u, ownedRecoveryCodes(), primary)
				}
				if !errors.Is(err, models.ErrLocalSignIn) {
					t.Fatal("superseded primary authorization changed MFA enrollment", err)
				}
				current, err := f.model.Client.User.Get(t.Context(), u.ID)
				if err != nil || current.TotpSecret != u.TotpSecret || current.TotpSecretConfirmed {
					t.Fatal("denied enrollment write changed MFA state", err)
				}
				if count, err := f.model.Client.RecoveryCode.Query().Count(t.Context()); err != nil || count != 0 {
					t.Fatal("denied enrollment replaced recovery codes", err)
				}
			})
		}
	}
}

func TestPrimaryGenerationSourceRollbackAndCallerSchema(t *testing.T) {
	for _, outcome := range []string{"rollback", "trigger failure", "different caller schema"} {
		t.Run(outcome, func(t *testing.T) {
			f, ctx := pendingOwnedLocalSession(t, true, loginproof.Password)
			proof, err := loginproof.Read(f.manager.GetString(ctx, loginproof.SessionKey), f.user.ID, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if outcome == "trigger failure" {
				if _, err = f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION fail_owned_primary_generation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned primary generation failure'; END $$; CREATE TRIGGER fail_owned_primary_generation BEFORE UPDATE OF primary_generation ON uem_session_account_generations FOR EACH ROW EXECUTE FUNCTION fail_owned_primary_generation()`); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := f.model.DB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			relation := "users"
			if outcome == "different caller schema" {
				relation = pgx.Identifier{f.pool.Config().ConnConfig.RuntimeParams["search_path"], relation}.Sanitize()
				if _, err = tx.ExecContext(t.Context(), `SET LOCAL search_path=pg_catalog`); err != nil {
					t.Fatal(err)
				}
			}
			_, err = tx.ExecContext(t.Context(), `UPDATE `+relation+` SET hash=hash||'x' WHERE uid='owner'`)
			if outcome == "trigger failure" && err == nil || outcome != "trigger failure" && err != nil {
				t.Fatal("unexpected primary generation mutation result", err)
			}
			if outcome == "different caller schema" {
				if _, err = tx.ExecContext(t.Context(), `UPDATE `+relation+` SET hash=left(hash,length(hash)-1) WHERE uid='owner'`); err != nil {
					t.Fatal(err)
				}
				err = tx.Commit()
			} else {
				err = tx.Rollback()
			}
			if err != nil {
				t.Fatal(err)
			}
			err = f.model.CheckLocalPrimary(t.Context(), f.user, loginproof.Password, nil, proof.Generation)
			if outcome == "different caller schema" {
				if !errors.Is(err, models.ErrLocalSignIn) {
					t.Fatal("caller schema redirected primary generation change", err)
				}
			} else if err != nil {
				t.Fatal("rolled back change invalidated primary evidence", err)
			}
		})
	}
}

func TestPrimaryGenerationUpgradeAndDisabledTrigger(t *testing.T) {
	f, ctx := pendingOwnedLocalSession(t, true, loginproof.Password)
	proof, err := loginproof.Read(f.manager.GetString(ctx, loginproof.SessionKey), f.user.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := sessiongeneration.Current(t.Context(), f.model.DB, f.user.ID, loginproof.Password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.model.DB.ExecContext(t.Context(), `ALTER TABLE users DISABLE TRIGGER uem_primary_generation`); err != nil {
		t.Fatal(err)
	}
	if err = f.store.Migrate(t.Context()); err == nil {
		t.Fatal("migration accepted disabled primary-generation enforcement")
	}
	if _, err = f.model.DB.ExecContext(t.Context(), `ALTER TABLE users ENABLE TRIGGER uem_primary_generation`); err != nil {
		t.Fatal(err)
	}
	if err = f.store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = f.model.CheckLocalPrimary(t.Context(), f.user, loginproof.Password, nil, proof.Generation); err != nil {
		t.Fatal("repeated startup replaced primary generation", err)
	}
	if _, err = f.model.DB.ExecContext(t.Context(), `DROP TRIGGER uem_primary_generation ON users; DROP FUNCTION uem_rotate_primary_generation(); ALTER TABLE uem_session_account_generations DROP COLUMN primary_generation; DELETE FROM uem_session_generation_migrations WHERE version=3`); err != nil {
		t.Fatal(err)
	}
	if err = f.store.Migrate(t.Context()); err != nil {
		t.Fatal("preceding generation schema failed to upgrade", err)
	}
	current, err := sessiongeneration.Current(t.Context(), f.model.DB, f.user.ID, loginproof.Password)
	if err != nil || current != completed {
		t.Fatal("primary migration changed completed-session generations", err)
	}
	if err = f.model.CheckLocalPrimary(t.Context(), f.user, loginproof.Password, nil, ""); !errors.Is(err, models.ErrLocalSignIn) {
		t.Fatal("preceding unbound primary evidence was admitted", err)
	}
	fresh, err := f.model.BeginLocalMFA(t.Context(), f.user, loginproof.Password, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.model.CheckLocalPrimary(t.Context(), f.user, loginproof.Password, nil, fresh); err != nil {
		t.Fatal("new primary proof failed after upgrade", err)
	}
}

func TestPrimaryGenerationSurvivesFreshProcess(t *testing.T) {
	f, ctx := pendingOwnedLocalSession(t, true, loginproof.Password)
	raw := f.manager.GetString(ctx, loginproof.SessionKey)
	child := func(denied bool) {
		t.Helper()
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), binary, "-test.run=^TestPrimaryGenerationRestartChild$")
		command.Env = append(os.Environ(), "OPENUEM_PRIMARY_RESTART_CHECK=1", "OPENUEM_PRIMARY_RESTART_DSN="+f.pool.Config().ConnString(), "OPENUEM_PRIMARY_RESTART_PROOF="+raw)
		if denied {
			command.Env = append(command.Env, "OPENUEM_PRIMARY_RESTART_DENIED=1")
		}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatal("fresh-process primary generation check failed", err, string(output))
		}
	}
	child(false)
	if _, err := f.model.DB.ExecContext(t.Context(), `UPDATE authentications SET use_passwd=false; UPDATE authentications SET use_passwd=true`); err != nil {
		t.Fatal(err)
	}
	child(true)
}

func TestPrimaryGenerationRestartChild(t *testing.T) {
	if os.Getenv("OPENUEM_PRIMARY_RESTART_CHECK") != "1" {
		t.Skip("owned restart subprocess only")
	}
	m, err := models.New(os.Getenv("OPENUEM_PRIMARY_RESTART_DSN"), "pgx", "example.test")
	if err != nil {
		t.Fatal("restart database unavailable")
	}
	defer m.Close()
	if err = sessiongeneration.Migrate(t.Context(), m.DB); err != nil {
		t.Fatal("restart generation migration failed")
	}
	proof, err := loginproof.Read(os.Getenv("OPENUEM_PRIMARY_RESTART_PROOF"), "owner", time.Now())
	if err != nil {
		t.Fatal("restart primary proof invalid")
	}
	u, err := m.Client.User.Get(t.Context(), proof.UserID)
	if err != nil {
		t.Fatal("restart account unavailable")
	}
	err = m.CheckLocalPrimary(t.Context(), u, proof.Method, nil, proof.Generation)
	if os.Getenv("OPENUEM_PRIMARY_RESTART_DENIED") == "1" {
		if !errors.Is(err, models.ErrLocalSignIn) {
			t.Fatal("restart admitted obsolete primary generation")
		}
	} else if err != nil {
		t.Fatal("restart denied valid primary generation")
	}
}
