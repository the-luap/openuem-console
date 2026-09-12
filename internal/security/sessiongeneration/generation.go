package sessiongeneration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
)

const SessionKey = "local-generation"

var ErrChanged = errors.New("local authentication generation changed")

type Stamp struct {
	Version     int    `json:"version"`
	UserID      string `json:"user"`
	Method      string `json:"method"`
	Account     string `json:"account"`
	Policy      string `json:"policy"`
	Certificate string `json:"certificate,omitempty"`
}

type Queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Current reads generation identifiers. It does not authorize a user or verify
// credentials; admission must hold the configuration and account locks first.
func Current(ctx context.Context, q Queryer, uid, method string) (Stamp, error) {
	return current(ctx, q, uid, method, "generation")
}

// CurrentPrimary reads the independent account generation for pending MFA.
// Admission must already hold the same source locks as completed sessions.
func CurrentPrimary(ctx context.Context, q Queryer, uid, method string) (Stamp, error) {
	return current(ctx, q, uid, method, "primary_generation")
}

func current(ctx context.Context, q Queryer, uid, method, column string) (Stamp, error) {
	stamp := Stamp{Version: 1, UserID: uid, Method: method}
	if uid == "" || (method != loginproof.Password && method != loginproof.Certificate) {
		return Stamp{}, ErrChanged
	}
	err := q.QueryRowContext(ctx, `SELECT a.`+column+`::text,p.generation::text FROM uem_session_account_generations a CROSS JOIN uem_session_method_generations p WHERE a.user_id=$1 AND p.method=$2`, uid, method).Scan(&stamp.Account, &stamp.Policy)
	if errors.Is(err, sql.ErrNoRows) {
		return Stamp{}, ErrChanged
	}
	return stamp, err
}

func (s Stamp) Encode() string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

// CurrentCertificate must run after locking the source certificate and
// revocation registry. A serial alone is not proof of certificate authority.
func CurrentCertificate(ctx context.Context, q Queryer, serial int64) (string, error) {
	if serial <= 0 {
		return "", ErrChanged
	}
	var generation string
	err := q.QueryRowContext(ctx, `SELECT generation::text FROM uem_session_certificate_generations WHERE serial=$1`, serial).Scan(&generation)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrChanged
	}
	return generation, err
}

func Read(raw, uid, method string) (Stamp, error) {
	var s Stamp
	if raw == "" || len(raw) > 2048 || uid == "" {
		return s, ErrChanged
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&s) != nil || decoder.Decode(new(any)) != io.EOF || s.Version != 1 || s.UserID != uid || s.Method != method || (method != loginproof.Password && method != loginproof.Certificate) {
		return Stamp{}, ErrChanged
	}
	identifiers := []string{s.Account, s.Policy}
	if method == loginproof.Certificate {
		identifiers = append(identifiers, s.Certificate)
	} else if s.Certificate != "" {
		return Stamp{}, ErrChanged
	}
	for _, value := range identifiers {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed.String() != value || parsed.Version() != 4 || parsed.Variant() != uuid.RFC4122 {
			return Stamp{}, ErrChanged
		}
	}
	return s, nil
}

func Migrate(parent context.Context, db *sql.DB) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, Schema); err != nil {
		return err
	}
	return tx.Commit()
}
