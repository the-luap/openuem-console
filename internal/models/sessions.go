package models

import (
	"context"
	"errors"

	"entgo.io/ent/dialect/sql"

	ent "github.com/open-uem/ent"
	"github.com/open-uem/ent/sessions"
	"github.com/open-uem/openuem-console/internal/security/sessiontokens"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func (m *Model) CountAllSessions() (int, error) {
	count, err := m.Client.Sessions.Query().Count(context.Background())
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (m *Model) GetSessionsByPage(p partials.PaginationAndSort) ([]*ent.Sessions, error) {
	var err error
	var s []*ent.Sessions

	query := m.Client.Sessions.Query().WithOwner().Limit(p.PageSize).Offset((p.CurrentPage - 1) * p.PageSize)

	switch p.SortBy {
	case "token":
		if p.SortOrder == "asc" {
			query = query.Order(ent.Asc(sessions.FieldID))
		} else {
			query = query.Order(ent.Desc(sessions.FieldID))
		}
	case "uid":
		if p.SortOrder == "asc" {
			query = query.Order(ent.Asc(sessions.OwnerColumn))
		} else {
			query = query.Order(ent.Desc(sessions.OwnerColumn))
		}
	case "expiry":
		if p.SortOrder == "asc" {
			query = query.Order(ent.Asc(sessions.FieldExpiry))
		} else {
			query = query.Order(ent.Desc(sessions.FieldExpiry))
		}
	default:
		query = query.Order(ent.Desc(sessions.OwnerColumn))
	}

	s, err = query.All(context.Background())
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (m *Model) DeleteSession(token string) error {
	if err := m.Client.Sessions.DeleteOneID(token).Exec(context.Background()); err != nil {
		return err
	}
	return nil
}

func (m *Model) GetSessionsTokens() ([]*ent.Sessions, error) {
	return m.Client.Sessions.Query().Select(sessions.FieldID).All(context.Background())
}

// UpdateSessionToken preserves data, expiry and ownership in one statement.
// Concurrent migrations cannot leave a second row after a failed delete.
func (m *Model) UpdateSessionToken(tokenID string, newTokenID string) error {
	count, err := m.Client.Sessions.Update().Where(sessions.ID(tokenID)).Modify(func(update *sql.UpdateBuilder) { update.Set(sessions.FieldID, newTokenID) }).Save(context.Background())
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("session token no longer exists")
	}
	return nil
}

// AddUserToSession resolves one indexed record and verifies its configured token
// representation. The final UPDATE cannot recreate a concurrently deleted row.
func (m *Model) AddUserToSession(ctx context.Context, token string, userID string, encryptionMasterKey string) error {
	var record string
	err := m.DB.QueryRowContext(ctx, `SELECT token FROM sessions s WHERE s.token_lookup=$1 AND NOT EXISTS(SELECT 1 FROM sessions_revocations r WHERE r.token_lookup=s.token_lookup)`, sessiontokens.Lookup(token)).Scan(&record)
	if err != nil {
		return err
	}
	plain, encrypted, err := sessiontokens.Decode(record, encryptionMasterKey)
	if err != nil {
		return err
	}
	if plain != token || (encryptionMasterKey != "" && !encrypted) {
		return errors.New("session token record does not match its encryption configuration")
	}
	return m.Client.Sessions.UpdateOneID(record).SetOwnerID(userID).Exec(ctx)
}
