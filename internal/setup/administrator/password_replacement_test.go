package administrator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/open-uem/openuem-console/internal/models"
)

func TestProtectedAdministratorPasswordReplacementTransaction(t *testing.T) {
	m := accountModel(t)
	if err := m.Client.Authentication.Create().SetUsePasswd(true).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	config := Config{UserID: "first-admin", PasswordFile: passwordFile(t, testPassword)}
	if _, err := Initialize(ctx, m.DB, config); err != nil {
		t.Fatal(err)
	}
	user, err := m.Client.User.Get(ctx, config.UserID)
	if err != nil {
		t.Fatal(err)
	}
	proof := models.PasswordReplacementProof{Kind: models.PasswordReplacementInitial, PasswordDigest: models.PasswordReplacementDigest(user.Hash), ExpiresAt: time.Now().Add(time.Minute)}
	if err := m.ChangePasswordWithProof(ctx, config.UserID, testPassword, proof); !errors.Is(err, models.ErrPasswordUnchanged) {
		t.Fatal("initial password reuse accepted", err)
	}
	if err := m.Client.Sessions.Create().SetID("initial-session").SetData([]byte("synthetic-session")).SetExpiry(time.Now().Add(time.Hour)).SetOwnerID(config.UserID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := m.DB.Exec(`CREATE FUNCTION reject_password_session_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic session failure'; END $$; CREATE TRIGGER reject_password_session_delete BEFORE DELETE ON sessions FOR EACH ROW EXECUTE FUNCTION reject_password_session_delete()`); err != nil {
		t.Fatal(err)
	}
	if err := m.ChangePasswordWithProof(ctx, config.UserID, "Replacement-Password-123456!", proof); !errors.Is(err, models.ErrPasswordReplacement) {
		t.Fatal("session retirement failure was not rejected", err)
	}
	unchanged, err := m.Client.User.Get(ctx, config.UserID)
	if err != nil || unchanged.Hash != user.Hash || unchanged.Register != user.Register {
		t.Fatal("failed session retirement committed a password", err)
	}
	if _, err := m.DB.Exec(`DROP TRIGGER reject_password_session_delete ON sessions`); err != nil {
		t.Fatal(err)
	}
	expired := proof
	expired.ExpiresAt = time.Now().Add(-time.Second)
	if err := m.ChangePasswordWithProof(ctx, config.UserID, "Expired-Password-123456!", expired); !errors.Is(err, models.ErrPasswordReplacement) {
		t.Fatal("expired proof accepted", err)
	}
	var wg sync.WaitGroup
	winners := make(chan string, 4)
	for _, password := range []string{"Concurrent-One_Password-123456!", "Concurrent-Two_Password-123456!", "Concurrent-Three_Password-123456!", "Concurrent-Four_Password-123456!"} {
		wg.Go(func() {
			err := m.ChangePasswordWithProof(ctx, config.UserID, password, proof)
			if err == nil {
				winners <- password
			} else if !errors.Is(err, models.ErrPasswordReplacement) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	close(winners)
	if len(winners) != 1 {
		t.Fatal("password proof did not allow exactly one commit", len(winners))
	}
	winner := <-winners
	current, err := m.Client.User.Get(ctx, config.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if matches, err := argon2id.ComparePasswordAndHash(winner, current.Hash); err != nil || !matches {
		t.Fatal("winning password was not retained", err)
	}
	var sessions int
	if err := m.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_sessions=$1`, config.UserID).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatal("password replacement retained old session rows", sessions, err)
	}
	if err := m.ChangePasswordWithProof(ctx, config.UserID, "Replayed-Password-123456!", proof); !errors.Is(err, models.ErrPasswordReplacement) {
		t.Fatal("old verified proof could replace the new password", err)
	}
}
