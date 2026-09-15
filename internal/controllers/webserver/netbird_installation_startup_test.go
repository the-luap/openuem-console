package webserver

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/controllers/webserver/handlers"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestNetbirdInstallationAndRemovalRuntimeBindsStoresAndJoinsWithoutBroker(t *testing.T) {
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for isolated inventory startup integration")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", u.Hostname())
	admin, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { admin.Close() })
	schema := "installation_startup_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.ExecContext(t.Context(), `CREATE SCHEMA `+schema)
	require.NoError(t, err)
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	db, err := sql.Open("pgx", u.String())
	require.NoError(t, err)
	db.SetMaxOpenConns(8)
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	t.Cleanup(func() {
		client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := admin.ExecContext(ctx, `DROP SCHEMA `+schema+` CASCADE`)
		require.NoError(t, err)
	})
	require.NoError(t, client.Schema.Create(t.Context()))
	permissions, err := access.NewStore(db)
	require.NoError(t, err)
	require.NoError(t, permissions.Migrate(t.Context()))
	w := &WebServer{Handler: &handlers.Handler{Model: &models.Model{DB: db, Client: client}, Access: permissions, EncryptionMasterKey: strings.Repeat("k", 32)}}
	require.NoError(t, w.startInventoryRefresh(t.Context()))
	t.Cleanup(w.stopInventoryRefresh)
	require.NotNil(t, w.Handler.NetbirdInstallations)
	require.NotNil(t, w.Handler.NetbirdRemovals)
	require.NotNil(t, w.Handler.NetbirdRemovalRecoveries)
	require.NotNil(t, w.Handler.NetbirdRemovalAbsences)
	manifest := w.Handler.NetbirdRemovalRecoveries
	require.NotNil(t, w.Handler.NetbirdRemovalStageCleanups)
	stageCleanup := w.Handler.NetbirdRemovalStageCleanups
	absence := w.Handler.NetbirdRemovalAbsences
	installation := w.Handler.NetbirdInstallations
	removal := w.Handler.NetbirdRemovals
	require.NoError(t, w.startInventoryRefresh(t.Context()))
	require.Same(t, installation, w.Handler.NetbirdInstallations)
	require.Same(t, removal, w.Handler.NetbirdRemovals)
	require.Same(t, manifest, w.Handler.NetbirdRemovalRecoveries)
	require.Same(t, absence, w.Handler.NetbirdRemovalAbsences)
	require.Same(t, stageCleanup, w.Handler.NetbirdRemovalStageCleanups)
	done := make(chan struct{})
	go func() { w.stopInventoryRefresh(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("inventory startup did not join installation, removal, continuation, absence and stage cleanup workers")
	}
	select {
	case <-w.inventoryDone:
	default:
		t.Fatal("inventory shutdown left workers running")
	}
}
