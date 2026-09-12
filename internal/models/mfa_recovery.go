package models

import (
	"context"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/open-uem/ent/recoverycode"
	"github.com/open-uem/ent/user"
)

// ConsumeRecoveryCode accepts only the request that changes the verified record
// from unused to used. Hash comparison does not hold a database lock.
func (m *Model) ConsumeRecoveryCode(parent context.Context, uid, code string) (bool, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// Generated codes have 16 ASCII characters; retain compatibility with longer
	// legacy values without accepting unbounded password-comparison input.
	if uid == "" || len(code) == 0 || len(code) > 256 {
		return false, nil
	}
	hashes, err := m.Client.RecoveryCode.Query().Where(recoverycode.HasUserWith(user.ID(uid)), recoverycode.Used(false)).All(ctx)
	if err != nil {
		return false, err
	}
	for _, hash := range hashes {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		match, err := argon2id.ComparePasswordAndHash(code, hash.Code)
		if err != nil || !match {
			continue
		}
		// Keep a canceled statement from committing later if its row lock is
		// released while the driver is still delivering the cancellation.
		tx, err := m.Client.Tx(ctx)
		if err != nil {
			return false, err
		}
		defer tx.Rollback()
		// Recheck ownership and the exact stored hash as well as the unused bit:
		// replacement, deletion or another consumer invalidates this snapshot.
		count, err := tx.RecoveryCode.Update().SetUsed(true).Where(
			recoverycode.ID(hash.ID), recoverycode.Code(hash.Code), recoverycode.Used(false),
			recoverycode.HasUserWith(user.ID(uid)),
		).Save(ctx)
		if err != nil || count != 1 {
			return false, err
		}
		if err = tx.Commit(); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, ctx.Err()
}
