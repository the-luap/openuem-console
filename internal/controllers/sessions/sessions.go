package sessions

import (
	"context"
	"fmt"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SessionManager struct {
	Manager *scs.SessionManager
	Pool    *pgxpool.Pool
}

func New(dbUrl string, sessionLifetimeInMinutes int, encryptionMasterKey string) (*SessionManager, error) {
	var err error
	sm := SessionManager{}

	sm.Pool, err = pgxpool.New(context.Background(), dbUrl)
	if err != nil {
		return nil, fmt.Errorf("initialize session database: %w", err)
	}

	sm.Manager = scs.New()
	sm.Manager.Lifetime = time.Duration(sessionLifetimeInMinutes) * time.Minute
	sm.Manager.Store = NewPostgresStore(sm.Pool, encryptionMasterKey)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err = sm.Manager.Store.(*PostgresStore).Migrate(ctx); err != nil {
		sm.Close()
		return nil, fmt.Errorf("migrate session store: %w", err)
	}
	sm.Manager.Cookie.Secure = true
	return &sm, nil
}

func (s *SessionManager) Close() {
	if s == nil {
		return
	}
	if s.Manager != nil {
		if store, ok := s.Manager.Store.(*PostgresStore); ok {
			store.StopCleanup()
		}
	}
	if s.Pool != nil {
		s.Pool.Close()
	}
}
