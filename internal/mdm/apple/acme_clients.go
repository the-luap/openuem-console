package apple

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

func (s *Store) acmeRegistryKey(ctx context.Context, tx *sql.Tx, tenant int) ([]byte, error) {
	var encrypted []byte
	err := tx.QueryRowContext(ctx, `SELECT encrypted_key FROM mdm_apple_acme_registry_keys WHERE tenant_id=$1`, tenant).Scan(&encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		key := make([]byte, 32)
		defer clear(key)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		encrypted, err = s.secrets.seal(key, secretPurpose(tenant, "acme", "registry_key"))
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_acme_registry_keys(tenant_id,encrypted_key) VALUES($1,$2) ON CONFLICT DO NOTHING`, tenant, encrypted); err != nil {
			return nil, err
		}
		// A concurrent first writer may have installed a different random key.
		err = tx.QueryRowContext(ctx, `SELECT encrypted_key FROM mdm_apple_acme_registry_keys WHERE tenant_id=$1`, tenant).Scan(&encrypted)
	}
	if err != nil {
		return nil, err
	}
	key, err := s.secrets.open(encrypted, secretPurpose(tenant, "acme", "registry_key"))
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		clear(key)
		return nil, errors.New("invalid ACME registry key")
	}
	return key, nil
}

func acmeClientHash(key []byte, client acmeClient) (string, []byte, error) {
	data, err := json.Marshal(client)
	if err != nil {
		return "", nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("openuem/apple/acme/client/v1\x00"))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil)), data, nil
}

// Every new claim and its command are committed together. Known identifiers
// remain bound to their enrollment after cancellation, removal and deletion.
// A fresh enrollment needs a new issuer-authorized identifier. System and User
// profiles on the same native enrollment share this ownership namespace.
func (s *Store) reserveACMEClients(ctx context.Context, tx *sql.Tx, d *Device, p *Profile) error {
	clients, err := acmeProfileClients(p, d)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProfilePrerequisite, err)
	}
	if len(clients) == 0 {
		return nil
	}
	var unresolved bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_acme_legacy_profiles WHERE tenant_id=$1 AND state IN ('pending','unresolved'))`, d.TenantID).Scan(&unresolved); err != nil {
		return err
	}
	if unresolved {
		return fmt.Errorf("%w: review unresolved historical profile archives before assigning ACME identities", ErrProfilePrerequisite)
	}
	return s.recordACMEClients(ctx, tx, d.TenantID, d.ID, clients, false)
}

func (s *Store) recordACMEClients(ctx context.Context, tx *sql.Tx, tenant int, device string, clients []acmeClient, legacy bool) error {
	if len(clients) == 0 {
		return nil
	}
	key, err := s.acmeRegistryKey(ctx, tx, tenant)
	if err != nil {
		return err
	}
	defer clear(key)
	type claim struct {
		hash  string
		plain []byte
	}
	claims := make([]claim, 0, len(clients))
	defer func() {
		for _, item := range claims {
			clear(item.plain)
		}
	}()
	for _, client := range clients {
		hash, plain, err := acmeClientHash(key, client)
		if err != nil {
			return err
		}
		claims = append(claims, claim{hash, plain})
	}
	// A composite profile may reference several clients. All replicas acquire
	// conflicting key rows in the same order; no global tenant lock is held.
	slices.SortFunc(claims, func(a, b claim) int {
		if a.hash < b.hash {
			return -1
		}
		if a.hash > b.hash {
			return 1
		}
		return 0
	})
	for _, item := range claims {
		encrypted, err := s.secrets.seal(item.plain, secretPurpose(tenant, "acme-client/"+item.hash, "reference"))
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_acme_clients(tenant_id,client_hash,device_id,encrypted_client) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, tenant, item.hash, device, encrypted); err != nil {
			return err
		}
		if legacy {
			// Previously reused identifiers cannot be assigned a trustworthy sole
			// owner. Retire those identifiers; new issuer identifiers still work.
			if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_acme_clients SET device_id=NULL,conflicted=true WHERE tenant_id=$1 AND client_hash=$2 AND device_id IS DISTINCT FROM $3::uuid`, tenant, item.hash, device); err != nil {
				return err
			}
			continue
		}
		var owner sql.NullString
		if err = tx.QueryRowContext(ctx, `SELECT device_id FROM mdm_apple_acme_clients WHERE tenant_id=$1 AND client_hash=$2`, tenant, item.hash).Scan(&owner); err != nil {
			return err
		}
		if !owner.Valid || owner.String != device {
			return fmt.Errorf("%w: an ACME client identifier is already bound to another enrollment or has conflicting historical use; obtain a new identifier from the issuer", ErrProfilePrerequisite)
		}
	}
	return nil
}

// Migrate calls this while holding its advisory transaction lock. Pagination
// bounds memory; reading old references never invokes issuer discovery or key
// generation. Unrecoverable history remains visible for administrative review.
func (s *Store) indexLegacyACMEClients(ctx context.Context, tx *sql.Tx) error {
	for {
		rows, err := tx.QueryContext(ctx, `SELECT id,tenant_id,device_id,profile_revision_id FROM mdm_apple_acme_legacy_profiles WHERE state='pending' ORDER BY tenant_id,id LIMIT 100`)
		if err != nil {
			return err
		}
		type record struct {
			id, device string
			tenant     int
			snapshot   sql.NullString
		}
		batch := []record{}
		for rows.Next() {
			var row record
			if err = rows.Scan(&row.id, &row.tenant, &row.device, &row.snapshot); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, row)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		for _, row := range batch {
			state := "unresolved"
			if row.snapshot.Valid {
				p, err := s.profileRevisionPayload(ctx, tx, row.tenant, row.snapshot.String)
				if err != nil && !errors.Is(err, ErrProfileRevision) {
					return err
				}
				if err == nil {
					clients, parseErr := acmeLegacyClients(p.Payload)
					clear(p.Payload)
					if parseErr == nil {
						if err = s.recordACMEClients(ctx, tx, row.tenant, row.device, clients, true); err != nil {
							return err
						}
						state = "indexed"
					}
				}
			}
			if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_acme_legacy_profiles SET state=$2 WHERE id=$1 AND state='pending'`, row.id, state); err != nil {
				return err
			}
		}
	}
}
