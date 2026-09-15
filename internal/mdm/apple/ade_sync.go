package apple

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/open-uem/openuem-console/internal/mdm/ade"
)

type ADEDevice struct {
	Serial        string    `json:"serial_number"`
	Model         string    `json:"model"`
	OS            string    `json:"os"`
	Family        string    `json:"device_family"`
	ProfileStatus string    `json:"profile_status"`
	ProfileID     string    `json:"profile_uuid"`
	Assigned      bool      `json:"-"`
	ObservedAt    time.Time `json:"-"`
}

type adeChange struct {
	Serial   string          `json:"serial"`
	Assigned bool            `json:"assigned"`
	At       *time.Time      `json:"operation_at"`
	Payload  json.RawMessage `json:"payload"`
}

var errADEAmbiguous = errors.New("ambiguous ADE device change")

func adeChanges(devices []ade.Device, delta bool) ([]adeChange, error) {
	selected := make(map[string]adeChange, len(devices))
	for _, d := range devices {
		v := ADEDevice{Serial: d.Serial, Model: d.Model, OS: d.OS, Family: d.Family, ProfileStatus: d.ProfileStatus, ProfileID: d.ProfileID}
		payload, _ := json.Marshal(v)
		c := adeChange{Serial: d.Serial, Assigned: d.Operation != "deleted", Payload: payload}
		if delta {
			at := d.OperationAt.UTC()
			c.At = &at
		}
		if old, ok := selected[c.Serial]; ok {
			if !delta {
				if !bytes.Equal(old.Payload, c.Payload) {
					return nil, errADEAmbiguous
				}
				continue
			}
			if c.At.Before(*old.At) {
				continue
			}
			if c.At.Equal(*old.At) {
				if old.Assigned != c.Assigned || c.Assigned && !bytes.Equal(old.Payload, c.Payload) {
					return nil, errADEAmbiguous
				}
				continue
			}
		}
		selected[c.Serial] = c
	}
	serials := make([]string, 0, len(selected))
	for serial := range selected {
		serials = append(serials, serial)
	}
	sort.Strings(serials)
	changes := make([]adeChange, 0, len(serials))
	for _, serial := range serials {
		changes = append(changes, selected[serial])
	}
	return changes, nil
}

func (s *Store) ADEDevices(ctx context.Context, tenant int, id, after string) ([]ADEDevice, string, error) {
	if after != "" && !ade.ValidSerial(after) {
		return nil, "", ErrADE
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_ade_servers WHERE id=$1 AND tenant_id=$2)`, id, tenant).Scan(&exists); err != nil {
		return nil, "", err
	}
	if !exists {
		return nil, "", ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT payload,assigned,observed_at FROM mdm_apple_ade_devices WHERE tenant_id=$1 AND server_id=$2 AND serial>$3 ORDER BY serial LIMIT 101`, tenant, id, after)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	list := []ADEDevice{}
	next := ""
	for rows.Next() {
		var wire []byte
		var d ADEDevice
		if err = rows.Scan(&wire, &d.Assigned, &d.ObservedAt); err != nil {
			return nil, "", err
		}
		if json.Unmarshal(wire, &d) != nil {
			return nil, "", ErrADE
		}
		if len(list) == 100 {
			next = list[99].Serial
			break
		}
		list = append(list, d)
	}
	return list, next, rows.Err()
}

func (s *Store) adeSyncFailure(ctx context.Context, tx *sql.Tx, tenant int, id string, cause error) error {
	code, after := "service_unavailable", 5*time.Minute
	var retry *ade.RetryError
	switch {
	case errors.As(cause, &retry):
		code, after = "throttled", retry.After
	case errors.Is(cause, ade.ErrToken):
		code, after = "token_expired", 24*time.Hour
	case errors.Is(cause, ade.ErrAuthorization):
		code, after = "token_rejected", 24*time.Hour
	case errors.Is(cause, ErrADEAccount):
		code, after = "account_changed", 24*time.Hour
	case errors.Is(cause, ade.ErrCursor), errors.Is(cause, errADEAmbiguous):
		if err := resetADEFetch(ctx, tx, tenant, id); err != nil {
			return err
		}
		code, after = "cursor_reset", time.Second
	}
	next := time.Now().Add(after)
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_ade_servers SET attempted_at=clock_timestamp(),sync_error=$3,next_sync_at=GREATEST($4,retry_after),retry_after=CASE WHEN $3='throttled' THEN $4 ELSE retry_after END WHERE tenant_id=$1 AND id=$2`, tenant, id, code, next)
	if err != nil {
		return err
	}
	if err = auditOutcome(ctx, tx, tenant, "system", "apple.ade.sync.failed", id, "failure"); err != nil {
		return err
	}
	return tx.Commit()
}

// One page and its cursor commit together under the same connection row lock.
// Concurrent replicas skip a live owner; renewal/disable waits for this bounded
// operation and cannot let its response overwrite a newer credential revision.
func (s *Store) syncADEServer(ctx context.Context, tenant int, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var sealed []byte
	var expectedHash, server, organization, mode, generation, cursor string
	var cursorAt *time.Time
	var pages int
	err = tx.QueryRowContext(ctx, `SELECT token,token_hash,apple_server_id,apple_organization_id,sync_mode,sync_generation,sync_cursor,cursor_updated_at,page_count FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2 AND status='connected' AND next_sync_at<=clock_timestamp() AND (retry_after IS NULL OR retry_after<=clock_timestamp()) FOR UPDATE SKIP LOCKED`, tenant, id).Scan(&sealed, &expectedHash, &server, &organization, &mode, &generation, &cursor, &cursorAt, &pages)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	fail := func(err error) error { return s.adeSyncFailure(ctx, tx, tenant, id, err) }
	if cursor != "" && (cursorAt == nil || cursorAt.Before(time.Now().Add(-6*24*time.Hour))) {
		return fail(ade.ErrCursor)
	}
	if pages >= 10000 {
		return fail(ade.ErrCursor)
	}
	plain, err := s.secrets.open(sealed, secretPurpose(tenant, id, "ade_token"))
	if err != nil {
		return fail(ade.ErrToken)
	}
	defer clear(plain)
	if digest(plain) != expectedHash {
		return fail(ade.ErrToken)
	}
	token, err := ade.ParseToken(plain, time.Now())
	if err != nil {
		return fail(ade.ErrToken)
	}
	defer token.Close()
	if s.adeService == nil {
		return fail(ErrADE)
	}
	client := s.adeService(token)
	if client == nil {
		return fail(ErrADE)
	}
	defer client.Close()
	// Reserve time for recording a network failure even after a request timeout.
	network, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	account, err := client.Account(network)
	if err != nil {
		return fail(err)
	}
	if account.ServerID != server || account.OrganizationID != organization {
		return fail(ErrADEAccount)
	}
	page, err := client.Devices(network, cursor, mode == "delta")
	stop()
	if err != nil {
		return fail(err)
	}
	if !token.ExpiresAt().After(time.Now()) {
		return fail(ade.ErrToken)
	}
	changes, err := adeChanges(page.Devices, mode == "delta")
	if err != nil {
		return fail(err)
	}
	wire, err := json.Marshal(changes)
	if err != nil {
		return ErrADE
	}
	if page.More {
		var seen bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_ade_cursors WHERE server_id=$1 AND generation=$2 AND cursor_hash=$3)`, id, generation, digest([]byte(page.Cursor))).Scan(&seen); err != nil {
			return err
		}
		if seen {
			return fail(ade.ErrCursor)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_cursors(server_id,generation,cursor_hash) VALUES($1,$2,$3)`, id, generation, digest([]byte(page.Cursor))); err != nil {
			return err
		}
	}
	if mode == "full" {
		var ambiguous bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM jsonb_to_recordset($4::jsonb) AS x(serial text,payload jsonb)
 JOIN mdm_apple_ade_fetch f ON f.tenant_id=$1 AND f.server_id=$2 AND f.generation=$3 AND f.serial=x.serial WHERE f.payload<>x.payload)`, tenant, id, generation, wire).Scan(&ambiguous)
		if err != nil {
			return err
		}
		if ambiguous {
			return fail(errADEAmbiguous)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_fetch(tenant_id,server_id,generation,serial,payload)
 SELECT $1,$2,$3,x.serial,x.payload FROM jsonb_to_recordset($4::jsonb) AS x(serial text,payload jsonb)
 ON CONFLICT(tenant_id,server_id,generation,serial) DO UPDATE SET payload=excluded.payload`, tenant, id, generation, wire)
		if err != nil {
			return err
		}
		if !page.More {
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_devices d SET assigned=false,operation_at=NULL,observed_at=clock_timestamp()
 WHERE tenant_id=$1 AND server_id=$2 AND assigned AND NOT EXISTS(SELECT 1 FROM mdm_apple_ade_fetch f WHERE f.tenant_id=d.tenant_id AND f.server_id=d.server_id AND f.generation=$3 AND f.serial=d.serial)`, tenant, id, generation)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_devices(tenant_id,server_id,serial,assigned,payload,operation_at)
 SELECT tenant_id,server_id,serial,true,payload,NULL FROM mdm_apple_ade_fetch WHERE tenant_id=$1 AND server_id=$2 AND generation=$3
 ON CONFLICT(tenant_id,server_id,serial) DO UPDATE SET assigned=true,payload=excluded.payload,operation_at=NULL,observed_at=clock_timestamp()`, tenant, id, generation)
			if err != nil {
				return err
			}
		}
	} else {
		var ambiguous bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM jsonb_to_recordset($3::jsonb) AS x(serial text,assigned boolean,operation_at timestamptz,payload jsonb)
 JOIN mdm_apple_ade_devices d ON d.tenant_id=$1 AND d.server_id=$2 AND d.serial=x.serial AND d.operation_at=x.operation_at
 WHERE d.assigned<>x.assigned OR (x.assigned AND d.payload<>x.payload))`, tenant, id, wire).Scan(&ambiguous)
		if err != nil {
			return err
		}
		if ambiguous {
			return fail(errADEAmbiguous)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_devices AS d(tenant_id,server_id,serial,assigned,payload,operation_at)
 SELECT $1,$2,x.serial,x.assigned,x.payload,x.operation_at FROM jsonb_to_recordset($3::jsonb) AS x(serial text,assigned boolean,payload jsonb,operation_at timestamptz)
 ON CONFLICT(tenant_id,server_id,serial) DO UPDATE SET assigned=excluded.assigned,payload=CASE WHEN excluded.assigned THEN excluded.payload ELSE d.payload END,operation_at=excluded.operation_at,observed_at=clock_timestamp()
 WHERE d.operation_at IS NULL OR excluded.operation_at>d.operation_at`, tenant, id, wire)
		if err != nil {
			return err
		}
	}
	if !page.More {
		if _, err = tx.ExecContext(ctx, `DELETE FROM mdm_apple_ade_fetch WHERE tenant_id=$1 AND server_id=$2`, tenant, id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM mdm_apple_ade_cursors WHERE server_id=$1`, id); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_servers SET sync_cursor=$3,cursor_updated_at=clock_timestamp(),attempted_at=clock_timestamp(),sync_error='',retry_after=NULL,
 next_sync_at=CASE WHEN $4 THEN clock_timestamp() ELSE clock_timestamp()+interval '1 hour' END,
 sync_mode=CASE WHEN $4 THEN sync_mode ELSE 'delta' END,synced_at=CASE WHEN $4 THEN synced_at ELSE clock_timestamp() END,
 sync_generation=CASE WHEN $4 THEN sync_generation ELSE gen_random_uuid() END,page_count=CASE WHEN $4 THEN page_count+1 ELSE 0 END
 WHERE tenant_id=$1 AND id=$2`, tenant, id, page.Cursor, page.More)
	if err != nil {
		return err
	}
	if err = audit(ctx, tx, tenant, "system", "apple.ade.sync.page", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReconcileADEServers(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT tenant_id,id FROM mdm_apple_ade_servers WHERE status='connected' AND next_sync_at<=clock_timestamp() AND (retry_after IS NULL OR retry_after<=clock_timestamp()) ORDER BY next_sync_at,id LIMIT 8`)
	if err != nil {
		return err
	}
	type candidate struct {
		tenant int
		id     string
	}
	list := []candidate{}
	for rows.Next() {
		var v candidate
		if err = rows.Scan(&v.tenant, &v.id); err != nil {
			rows.Close()
			return err
		}
		list = append(list, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range list {
		if err = s.syncADEServer(ctx, v.tenant, v.id); err != nil {
			return err
		}
	}
	return nil
}

// A dedicated loop keeps slow Apple assignment-service requests from consuming
// the APNs, identity-renewal and security-command maintenance budget.
func (s *Store) runADEServers(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		work, cancel := context.WithTimeout(ctx, 40*time.Second)
		if err := s.ReconcileADEServers(work); err != nil && ctx.Err() == nil {
			logger.Error("Apple automated enrollment synchronization failed")
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
