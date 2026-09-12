package sessions

import (
	"context"
	"log"
	"net/http"
	"time"
)

// Establish creates a fresh session and publishes its cookie only after all
// admission bookkeeping succeeds. Values must describe the newly verified
// identity/flow; no authority or recovery state is inherited from the old one.
func (s *SessionManager) Establish(ctx context.Context, writer http.ResponseWriter, values map[string]any, finish func(context.Context, string) error) (err error) {
	sm := s.Manager
	defer func() {
		if err == nil {
			return
		}
		// Error rendering can cause SCS to save again. Remove identity in memory
		// before cleanup, even if the database is unavailable or the request ended.
		_ = sm.Clear(ctx)
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if cleanupErr := sm.Destroy(cleanup); cleanupErr != nil {
			log.Print("[ERROR]: could not remove failed sign-in session")
		}
	}()
	if err = sm.Clear(ctx); err != nil {
		return err
	}
	if err = sm.RenewToken(ctx); err != nil {
		return err
	}
	for key, value := range values {
		sm.Put(ctx, key, value)
	}
	token, expiry, err := sm.Commit(ctx)
	if err != nil {
		return err
	}
	if finish != nil {
		if err = finish(ctx, token); err != nil {
			return err
		}
		// Final admission may attach generation metadata. Persist that state
		// before publishing its cookie, and retire the token if this write fails.
		if token, expiry, err = sm.Commit(ctx); err != nil {
			return err
		}
	}
	sm.WriteSessionCookie(ctx, writer, token, expiry)
	return nil
}
