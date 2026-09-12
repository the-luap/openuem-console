package sessions_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/sessiongeneration"
)

func TestCertificateGenerationPreservesDescriptionOtherRecordsAndStartup(t *testing.T) {
	f, ctx, cert := completedOwnedCertificateSession(t, true, "none")
	original, err := sessiongeneration.Read(f.manager.GetString(ctx, sessiongeneration.SessionKey), f.user.ID, loginproof.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.model.DB.ExecContext(t.Context(), `UPDATE certificates SET description='Owned updated description' WHERE serial=2;
INSERT INTO certificates(serial,uid,type,expiry) SELECT 3,'other-owned-user','user',expiry FROM certificates WHERE serial=2;
UPDATE certificates SET uid='another-owned-user' WHERE serial=3;
INSERT INTO revocations(serial,revoked,expiry) SELECT serial,clock_timestamp(),expiry FROM certificates WHERE serial=3;
UPDATE revocations SET serial=4 WHERE serial=3;
DELETE FROM revocations WHERE serial=4`); err != nil {
		t.Fatal(err)
	}
	if err = f.store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	current, err := sessiongeneration.CurrentCertificate(t.Context(), f.model.DB, cert.SerialNumber.Int64())
	if err != nil || current != original.Certificate {
		t.Fatal("description, another certificate or restart changed session generation", err)
	}
	if admitted, err := localSessionRequest(f, ctx); !admitted || err != nil {
		t.Fatal("benign certificate changes invalidated existing session", err)
	}
	original.Certificate = ""
	if err = f.model.CheckCertificateSession(t.Context(), f.user, cert, original.Encode()); !errors.Is(err, models.ErrLocalSignIn) {
		t.Fatal("older certificate metadata without a generation was admitted", err)
	}
}

func TestCertificateGenerationSourceRollbackAndCallerSchema(t *testing.T) {
	for _, source := range []string{"certificate", "revocation"} {
		for _, outcome := range []string{"rollback", "trigger failure", "different caller schema"} {
			t.Run(source+"/"+outcome, func(t *testing.T) {
				f, ctx, cert := completedOwnedCertificateSession(t, true, "none")
				original, err := sessiongeneration.CurrentCertificate(t.Context(), f.model.DB, cert.SerialNumber.Int64())
				if err != nil {
					t.Fatal(err)
				}
				if outcome == "trigger failure" {
					if _, err = f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION fail_owned_certificate_generation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned certificate generation failure'; END $$; CREATE TRIGGER fail_owned_certificate_generation BEFORE UPDATE ON uem_session_certificate_generations FOR EACH ROW EXECUTE FUNCTION fail_owned_certificate_generation()`); err != nil {
						t.Fatal(err)
					}
				}
				tx, err := f.model.DB.BeginTx(t.Context(), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				certificate, revocation := "certificates", "revocations"
				if outcome == "different caller schema" {
					schema := f.pool.Config().ConnConfig.RuntimeParams["search_path"]
					certificate = pgx.Identifier{schema, certificate}.Sanitize()
					revocation = pgx.Identifier{schema, revocation}.Sanitize()
					if _, err = tx.ExecContext(t.Context(), `SET LOCAL search_path=pg_catalog`); err != nil {
						t.Fatal(err)
					}
				}
				query := `UPDATE ` + certificate + ` SET uid='other-owned-user' WHERE serial=$1`
				restore := `UPDATE ` + certificate + ` SET uid='owner' WHERE serial=$1`
				if source == "revocation" {
					query = `INSERT INTO ` + revocation + `(serial,revoked,expiry) SELECT serial,clock_timestamp(),expiry FROM ` + certificate + ` WHERE serial=$1`
					restore = `DELETE FROM ` + revocation + ` WHERE serial=$1`
				}
				_, err = tx.ExecContext(t.Context(), query, cert.SerialNumber.Int64())
				if outcome == "trigger failure" && err == nil || outcome != "trigger failure" && err != nil {
					t.Fatal("unexpected generation write result", err)
				}
				if outcome == "different caller schema" {
					if _, err = tx.ExecContext(t.Context(), restore, cert.SerialNumber.Int64()); err != nil {
						t.Fatal(err)
					}
					err = tx.Commit()
				} else {
					err = tx.Rollback()
				}
				if err != nil {
					t.Fatal(err)
				}
				current, err := sessiongeneration.CurrentCertificate(t.Context(), f.model.DB, cert.SerialNumber.Int64())
				if err != nil {
					t.Fatal(err)
				}
				admitted, checkErr := localSessionRequest(f, ctx)
				if outcome == "different caller schema" {
					if current == original || admitted || checkErr == nil {
						t.Fatal("caller schema redirected the generation change", checkErr)
					}
				} else if current != original || !admitted || checkErr != nil {
					t.Fatal("rolled back source write changed authority", checkErr)
				}
			})
		}
	}
}

func TestCertificateGenerationStartupRejectsDisabledTriggers(t *testing.T) {
	for _, source := range []string{"certificate", "revocation"} {
		t.Run(source, func(t *testing.T) {
			f, ctx, _ := completedOwnedCertificateSession(t, true, "none")
			table, trigger := "certificates", "uem_certificate_generation"
			if source == "revocation" {
				table, trigger = "revocations", "uem_revocation_generation"
			}
			if _, err := f.model.DB.ExecContext(t.Context(), `ALTER TABLE `+table+` DISABLE TRIGGER `+trigger); err != nil {
				t.Fatal(err)
			}
			if err := f.store.Migrate(t.Context()); err == nil {
				t.Fatal("startup accepted a disabled certificate generation trigger")
			}
			if _, err := f.model.DB.ExecContext(t.Context(), `ALTER TABLE `+table+` ENABLE TRIGGER `+trigger); err != nil {
				t.Fatal(err)
			}
			if err := f.store.Migrate(t.Context()); err != nil {
				t.Fatal(err)
			}
			if admitted, err := localSessionRequest(f, ctx); !admitted || err != nil {
				t.Fatal("valid restart replaced the certificate generation", err)
			}
		})
	}
}

func TestCertificateGenerationUpgradeSeedsExistingRegistry(t *testing.T) {
	f, ctx, cert := completedOwnedCertificateSession(t, true, "none")
	old, err := sessiongeneration.Read(f.manager.GetString(ctx, sessiongeneration.SessionKey), f.user.ID, loginproof.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce the preceding installation, which has account/method generations
	// but no certificate-generation schema or certificate field in its sessions.
	if _, err = f.model.DB.ExecContext(t.Context(), `DROP TRIGGER uem_certificate_generation ON certificates;
DROP TRIGGER uem_revocation_generation ON revocations;
DROP FUNCTION uem_rotate_certificate_generation(); DROP FUNCTION uem_rotate_revocation_generation();
DROP TABLE uem_session_certificate_generations;
DELETE FROM uem_session_generation_migrations WHERE version=2`); err != nil {
		t.Fatal(err)
	}
	old.Certificate = ""
	if err = f.store.Migrate(t.Context()); err != nil {
		t.Fatal("preceding certificate registry failed migration", err)
	}
	base, err := sessiongeneration.Current(t.Context(), f.model.DB, f.user.ID, loginproof.Certificate)
	if err != nil || base.Account != old.Account || base.Policy != old.Policy {
		t.Fatal("certificate migration replaced unrelated generations", err)
	}
	if _, err = sessiongeneration.CurrentCertificate(t.Context(), f.model.DB, cert.SerialNumber.Int64()); err != nil {
		t.Fatal("existing certificate was not seeded", err)
	}
	if err = f.model.CheckCertificateSession(t.Context(), f.user, cert, old.Encode()); !errors.Is(err, models.ErrLocalSignIn) {
		t.Fatal("upgrade admitted a session without certificate generation", err)
	}
	current, err := f.model.CompleteLocalSession(t.Context(), f.user, loginproof.Certificate, cert, nil)
	if err != nil {
		t.Fatal("migrated certificate could not establish a new session", err)
	}
	if err = f.model.CheckCertificateSession(t.Context(), f.user, cert, current); err != nil {
		t.Fatal("new session using seeded generation failed", err)
	}
}
