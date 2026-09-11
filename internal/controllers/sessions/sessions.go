package sessions

import (
	"context"
	"log"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SessionManager struct {
	Manager *scs.SessionManager
	Pool    *pgxpool.Pool
}

func New(dbUrl string, sessionLifetimeInMinutes int, encryptionMasterKey string) *SessionManager {
	var err error
	sm := SessionManager{}

	sm.Pool, err = pgxpool.New(context.Background(), dbUrl)
	if err != nil {
		log.Println("[FATAL]: session manager could not contact the database")
		log.Fatal(err)
	}

	sm.Manager = scs.New()
	sm.Manager.Lifetime = time.Duration(sessionLifetimeInMinutes) * time.Minute
	sm.Manager.Store = NewPostgresStore(sm.Pool, encryptionMasterKey)
	sm.Manager.Cookie.Secure = true
	return &sm
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
