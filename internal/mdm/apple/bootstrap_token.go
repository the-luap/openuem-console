package apple

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// BootstrapToken exchanges opaque Mac authorization material only with the
// currently enrolled device identity. It has no console download endpoint.
// The check-in schema identifies this request by its certificate; UDID is optional.
func (s *Store) BootstrapToken(ctx context.Context, d *Device, message map[string]any) (map[string]any, error) {
	kind := stringValue(message, "MessageType")
	if !deviceChannelMessage(message) || (kind != "SetBootstrapToken" && kind != "GetBootstrapToken") {
		return nil, ErrUnauthorized
	}
	if value, exists := message["UDID"]; exists {
		if udid, ok := value.(string); !ok || udid == "" || udid != d.UDID {
			return nil, ErrUnauthorized
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	current, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 FOR UPDATE`, d.ID))
	if err != nil {
		return nil, err
	}
	if current.Status != "enrolled" || current.Family() != PlatformMacOS || !versionPattern.MatchString(current.OSVersion) || CompareVersions(current.OSVersion, "10.15") < 0 {
		return nil, ErrUnauthorized
	}
	if err = s.requireActiveIdentity(ctx, tx, d); err != nil {
		return nil, err
	}
	actor := "device:" + current.ID
	response := map[string]any{}
	if kind == "SetBootstrapToken" {
		var token []byte
		if value, exists := message["BootstrapToken"]; exists {
			var ok bool
			token, ok = value.([]byte)
			if !ok || len(token) > 64<<10 {
				return nil, errors.New("invalid bootstrap token data")
			}
		}
		if len(token) == 0 {
			if _, err = tx.ExecContext(ctx, `DELETE FROM mdm_apple_bootstrap_tokens WHERE device_id=$1 AND tenant_id=$2`, current.ID, current.TenantID); err != nil {
				return nil, err
			}
			if err = audit(ctx, tx, current.TenantID, actor, "apple.bootstrap_token.clear", current.ID); err != nil {
				return nil, err
			}
		} else {
			encrypted, err := s.secrets.seal(token, secretPurpose(current.TenantID, current.ID, "bootstrap_token"))
			if err != nil {
				return nil, err
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_bootstrap_tokens(device_id,tenant_id,encrypted_token,token_hash) VALUES($1,$2,$3,$4) ON CONFLICT(device_id) DO UPDATE SET encrypted_token=EXCLUDED.encrypted_token,token_hash=EXCLUDED.token_hash,updated_at=clock_timestamp()`, current.ID, current.TenantID, encrypted, digest(token)); err != nil {
				return nil, err
			}
			if err = audit(ctx, tx, current.TenantID, actor, "apple.bootstrap_token.store", current.ID); err != nil {
				return nil, err
			}
		}
		if err = s.reconcileDeviceUpdate(ctx, tx, current); err != nil {
			return nil, err
		}
	} else {
		var encrypted []byte
		err = tx.QueryRowContext(ctx, `SELECT encrypted_token FROM mdm_apple_bootstrap_tokens WHERE device_id=$1 AND tenant_id=$2`, current.ID, current.TenantID).Scan(&encrypted)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if err == nil {
			token, err := s.secrets.open(encrypted, secretPurpose(current.TenantID, current.ID, "bootstrap_token"))
			if err != nil {
				return nil, err
			}
			response["BootstrapToken"] = token
		}
		if err = audit(ctx, tx, current.TenantID, actor, "apple.bootstrap_token.read", current.ID); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return response, nil
}
