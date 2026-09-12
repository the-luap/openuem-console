//go:build linux || windows

package common_test

import (
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/sessiontokens"
)

func TestStartupSessionEncryptionPreservesLegacyRecords(t *testing.T) {
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for startup session migration")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "startup_sessions_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = db.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	t.Setenv("ENV", "test")
	m, err := models.New(u.String(), "pgx", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.Close()
		if _, err := db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		db.Close()
	})
	if err = m.Client.User.Create().SetID("owned-user").SetName("Owned migration user").Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	expiry := time.Date(2026, 1, 1, 0, 0, 0, 123456000, time.UTC)
	for _, token := range []string{"00", strings.Repeat("a", 43)} {
		if err = m.Client.Sessions.Create().SetID(token).SetData([]byte("owned data")).SetExpiry(expiry).SetOwnerID("owned-user").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	key := strings.Repeat("k", 32)
	var original map[string]bool
	for range 2 {
		manager, err := sessions.New(u.String(), 30, key)
		if err != nil {
			t.Fatal(err)
		}
		manager.Close()
		records, err := m.Client.Sessions.Query().WithOwner().All(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 2 {
			t.Fatal("startup migration duplicated or dropped a session", len(records))
		}
		keys := map[string]bool{}
		for _, record := range records {
			plain, encrypted, err := sessiontokens.Decode(record.ID, key)
			if err != nil || !encrypted || (plain != "00" && plain != strings.Repeat("a", 43)) || string(record.Data) != "owned data" || !record.Expiry.Equal(expiry) || record.Edges.Owner == nil || record.Edges.Owner.ID != "owned-user" {
				t.Fatal("startup migration lost data, expiry or ownership", err)
			}
			keys[record.ID] = true
			if original != nil && !original[record.ID] {
				t.Fatal("restart replaced an already encrypted token")
			}
		}
		original = keys
	}
}
