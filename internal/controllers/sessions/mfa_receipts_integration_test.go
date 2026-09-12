package sessions_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/mfaadmission"
	"github.com/open-uem/utils"
	"github.com/pquerna/otp/totp"
)

func ownedMFAEvidence(t *testing.T, user *ent.User, proof string, at time.Time) *mfaadmission.Evidence {
	t.Helper()
	code, err := totp.GenerateCode(user.TotpSecret, at)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := mfaadmission.TOTP(proof, user.ID, user.TotpSecret, code, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func TestMFAEvidenceCancellationRollsBackWrittenReceipts(t *testing.T) {
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
	u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned MFA user").SetPasswd(true).SetHash("owned verified hash").SetRegister(nats.REGISTER_APPROVED).SetUse2fa(true).SetTotpSecretConfirmed(true).SetTotpSecret("JBSWY3DPEHPK3PXP").Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	proof := loginproof.New(u.ID, loginproof.Password, u.Hash, time.Now())
	evidence := ownedMFAEvidence(t, u, proof, time.Now())
	if _, err = f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION hold_mfa_confirmation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock_shared(712036484); RETURN NEW; END $$; CREATE TRIGGER hold_mfa_confirmation BEFORE UPDATE OF register ON users FOR EACH ROW EXECUTE FUNCTION hold_mfa_confirmation()`); err != nil {
		t.Fatal(err)
	}
	tx, err := f.model.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if _, err = tx.ExecContext(t.Context(), `SELECT pg_advisory_xact_lock(712036484)`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.model.CompleteMFASignIn(ctx, u, loginproof.Password, evidence) }()
	deadline := time.Now().Add(4 * time.Second)
	for {
		var waiting bool
		if err = f.model.DB.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE users SET register=%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admission did not reach confirmation after writing its evidence")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("admission ignored cancellation after writing receipts", err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var receipts, counters int
	if err = f.model.DB.QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM uem_mfa_primary_consumptions),(SELECT count(*) FROM uem_mfa_totp_counters)`).Scan(&receipts, &counters); err != nil || receipts != 0 || counters != 0 {
		t.Fatal("cancellation retained uncommitted evidence", receipts, counters, err)
	}
	if err = f.model.CompleteMFASignIn(t.Context(), u, loginproof.Password, evidence); err != nil {
		t.Fatal("canceled evidence could not be retried", err)
	}
}

func TestMFAFinalAdmissionRejectsMismatchedPrimaryEvidence(t *testing.T) {
	f := newSessionFixture(t, false)
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
	u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned MFA user").SetPasswd(true).SetHash("owned verified hash").SetRegister(nats.REGISTER_APPROVED).SetUse2fa(true).SetTotpSecretConfirmed(true).SetTotpSecret("JBSWY3DPEHPK3PXP").Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(u.TotpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, proof := range []struct{ uid, method, credential string }{{u.ID, loginproof.Password, "other credential"}, {"other", loginproof.Password, u.Hash}, {u.ID, loginproof.Certificate, u.Hash}} {
		raw := loginproof.New(proof.uid, proof.method, proof.credential, time.Now())
		evidence, err := mfaadmission.TOTP(raw, proof.uid, u.TotpSecret, code, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err = f.model.CompleteMFASignIn(t.Context(), u, loginproof.Password, evidence); !errors.Is(err, mfaadmission.ErrRejected) {
			t.Fatal("mismatched primary evidence admitted a session", err)
		}
	}
	if err = f.model.AdmitLocalSignIn(t.Context(), u, loginproof.Password, models.LocalSignInComplete); !errors.Is(err, mfaadmission.ErrRejected) {
		t.Fatal("MFA completion admitted without evidence", err)
	}
	var count int
	if err = f.model.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_mfa_primary_consumptions`).Scan(&count); err != nil || count != 0 {
		t.Fatal("denied proof consumed another flow", count, err)
	}
}

func TestMFAReceiptsRollBackWithFailedConfirmation(t *testing.T) {
	for _, failure := range []string{"primary", "counter", "confirmation"} {
		t.Run(failure, func(t *testing.T) {
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
			u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned MFA user").SetPasswd(true).SetHash("owned verified hash").SetRegister(nats.REGISTER_APPROVED).SetUse2fa(true).SetTotpSecretConfirmed(true).SetTotpSecret("JBSWY3DPEHPK3PXP").Save(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			proof := loginproof.New(u.ID, loginproof.Password, u.Hash, time.Now())
			evidence := ownedMFAEvidence(t, u, proof, time.Now())
			table, event := "users", "UPDATE OF register"
			if failure == "primary" {
				table, event = "uem_mfa_primary_consumptions", "INSERT"
			}
			if failure == "counter" {
				table, event = "uem_mfa_totp_counters", "INSERT"
			}
			if _, err = f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION reject_mfa_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned MFA admission failure'; END $$; CREATE TRIGGER reject_mfa_receipt BEFORE `+event+` ON `+table+` FOR EACH ROW EXECUTE FUNCTION reject_mfa_receipt()`); err != nil {
				t.Fatal(err)
			}
			if err = f.model.CompleteMFASignIn(t.Context(), u, loginproof.Password, evidence); err == nil {
				t.Fatal("failed persistence admitted MFA")
			}
			var primary, counters int
			if err = f.model.DB.QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM uem_mfa_primary_consumptions),(SELECT count(*) FROM uem_mfa_totp_counters)`).Scan(&primary, &counters); err != nil {
				t.Fatal(err)
			}
			if primary != 0 || counters != 0 {
				t.Fatal("failed admission consumed evidence", primary, counters)
			}
			current, err := f.model.Client.User.Get(t.Context(), u.ID)
			if err != nil || current.Register != u.Register {
				t.Fatal("failed admission changed registration", err)
			}
			if _, err = f.model.DB.ExecContext(t.Context(), `DROP TRIGGER reject_mfa_receipt ON `+table); err != nil {
				t.Fatal(err)
			}
			if err = f.model.CompleteMFASignIn(t.Context(), u, loginproof.Password, evidence); err != nil {
				t.Fatal("rolled-back evidence could not be retried", err)
			}
			if err = f.model.CompleteMFASignIn(t.Context(), u, loginproof.Password, evidence); !errors.Is(err, mfaadmission.ErrRejected) {
				t.Fatal("committed evidence was reusable", err)
			}
		})
	}
}

func TestMFACountersSurviveStartupMigrationAndEquivalentSecretEncoding(t *testing.T) {
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
	u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned MFA user").SetPasswd(true).SetHash("owned verified hash").SetRegister(nats.REGISTER_APPROVED).SetUse2fa(true).SetTotpSecretConfirmed(true).SetTotpSecret("JBSWY3DPEHPK3PXP").Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	proof := loginproof.New(u.ID, loginproof.Password, u.Hash, now)
	evidence := ownedMFAEvidence(t, u, proof, now)
	if err = f.model.CompleteMFASignIn(t.Context(), u, loginproof.Password, evidence); err != nil {
		t.Fatal(err)
	}
	// A fresh test process connects to the same owned database and must still
	// reject the old proof and the counter with a newly generated proof.
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(t.Context(), binary, "-test.run=^TestMFAReceiptRestartChild$", "-test.count=1")
	child.Env = append(os.Environ(), "OPENUEM_MFA_RESTART_CHECK=1", "OPENUEM_MFA_RESTART_DATABASE_URL="+f.pool.Config().ConnString(), "OPENUEM_MFA_RESTART_PROOF="+proof, "OPENUEM_MFA_RESTART_TIME="+strconv.FormatInt(now.Unix(), 10))
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("fresh process accepted replayed evidence: %v\n%s", err, output)
	}
	// Startup migrations must preserve both kinds of one-use evidence.
	if err = f.store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = f.model.CompleteMFASignIn(t.Context(), u, loginproof.Password, evidence); !errors.Is(err, mfaadmission.ErrRejected) {
		t.Fatal("migration revived a consumed primary flow", err)
	}
	u, err = u.Update().SetTotpSecret(strings.ToLower(u.TotpSecret)).Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	proof = loginproof.New(u.ID, loginproof.Password, u.Hash, time.Now())
	if err = f.model.CompleteMFASignIn(t.Context(), u, loginproof.Password, ownedMFAEvidence(t, u, proof, now)); !errors.Is(err, mfaadmission.ErrRejected) {
		t.Fatal("new flow or equivalent key encoding replayed TOTP", err)
	}
	plain := u.TotpSecret
	ciphertext, err := utils.EncryptSensitiveField(plain, f.key)
	if err != nil {
		t.Fatal(err)
	}
	u, err = u.Update().SetTotpSecret(ciphertext).Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(plain, now)
	if err != nil {
		t.Fatal(err)
	}
	encodedEvidence, err := mfaadmission.TOTP(proof, u.ID, plain, code, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = f.model.CompleteMFASignIn(t.Context(), u, loginproof.Password, encodedEvidence); !errors.Is(err, mfaadmission.ErrRejected) {
		t.Fatal("encrypted storage revived the same TOTP counter", err)
	}
	u, err = u.Update().SetTotpSecret(plain).Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var receipts int
	if err = f.model.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_mfa_primary_consumptions`).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatal("rejected counter left a consumed primary receipt", receipts, err)
	}
	// The rejected transaction did not consume its flow; a newer valid counter
	// can complete it without changing primary authentication.
	if err = f.model.CompleteMFASignIn(t.Context(), u, loginproof.Password, ownedMFAEvidence(t, u, proof, now.Add(30*time.Second))); err != nil {
		t.Fatal("next valid counter could not complete the flow", err)
	}
	other, err := f.model.Client.User.Create().SetID("other").SetName("Other owned MFA user").SetPasswd(true).SetHash(u.Hash).SetRegister(nats.REGISTER_APPROVED).SetUse2fa(true).SetTotpSecretConfirmed(true).SetTotpSecret(u.TotpSecret).Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	otherProof := loginproof.New(other.ID, loginproof.Password, other.Hash, time.Now())
	if err = f.model.CompleteMFASignIn(t.Context(), other, loginproof.Password, ownedMFAEvidence(t, other, otherProof, now)); err != nil {
		t.Fatal("another account shared the replay counter", err)
	}
	u, err = u.Update().SetTotpSecret("KRSXG5DSNFXGOIDT").Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	newProof := loginproof.New(u.ID, loginproof.Password, u.Hash, time.Now())
	if err = f.model.CompleteMFASignIn(t.Context(), u, loginproof.Password, ownedMFAEvidence(t, u, newProof, time.Now())); err != nil {
		t.Fatal("new authenticator inherited the old key's counter", err)
	}
}

func TestMFAReceiptRestartChild(t *testing.T) {
	if os.Getenv("OPENUEM_MFA_RESTART_CHECK") != "1" {
		t.Skip("owned restart subprocess only")
	}
	m, err := models.New(os.Getenv("OPENUEM_MFA_RESTART_DATABASE_URL"), "pgx", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	u, err := m.Client.User.Get(t.Context(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	seconds, err := strconv.ParseInt(os.Getenv("OPENUEM_MFA_RESTART_TIME"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	for _, proof := range []string{os.Getenv("OPENUEM_MFA_RESTART_PROOF"), loginproof.New(u.ID, loginproof.Password, u.Hash, time.Now())} {
		evidence := ownedMFAEvidence(t, u, proof, time.Unix(seconds, 0))
		if err = m.CompleteMFASignIn(t.Context(), u, loginproof.Password, evidence); !errors.Is(err, mfaadmission.ErrRejected) {
			t.Fatal("fresh process accepted used MFA evidence", err)
		}
	}
}
