package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

func (s *Store) savePlatformInventory(ctx context.Context, tx *sql.Tx, d *Device, info map[string]any, model string) error {
	updateID := stringValue(info, "SoftwareUpdateDeviceID")
	if len(updateID) > 255 || strings.ContainsAny(updateID, "\x00\r\n") {
		return errors.New("invalid software update device identifier")
	}
	var silicon any
	if DetectPlatform(model) == PlatformMacOS {
		if value, ok := info["IsAppleSilicon"].(bool); ok {
			silicon = value
		}
	}
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET software_update_device_id=COALESCE(NULLIF($2,''),software_update_device_id),apple_silicon=COALESCE($3::boolean,apple_silicon) WHERE id=$1`, d.ID, updateID, silicon)
	return err
}

func (s *Store) saveSecurityInventory(ctx context.Context, tx *sql.Tx, d *Device, message map[string]any) error {
	if d.Family() != PlatformMacOS {
		return errors.New("Mac security inventory requires a Mac device")
	}
	info, ok := message["SecurityInfo"].(map[string]any)
	if !ok {
		return errors.New("SecurityInfo response is missing its dictionary")
	}
	// Recovery material belongs in encrypted escrow, never a generic inventory
	// JSON document. Keep only explicit non-secret capability evidence here.
	safe := map[string]any{}
	if management, ok := info["ManagementStatus"].(map[string]any); ok {
		values := map[string]any{}
		for _, key := range []string{"UserApprovedEnrollment", "EnrolledViaDEP", "IsUserEnrollment"} {
			if value, ok := management[key].(bool); ok {
				values[key] = value
			}
		}
		safe["ManagementStatus"] = values
	}
	if value := stringValue(info, "BootstrapTokenAllowedForAuthentication"); value == "allowed" || value == "disallowed" || value == "not supported" {
		safe["BootstrapTokenAllowedForAuthentication"] = value
	}
	if value, ok := info["BootstrapTokenRequiredForSoftwareUpdate"].(bool); ok {
		safe["BootstrapTokenRequiredForSoftwareUpdate"] = value
	}
	data, err := json.Marshal(safe)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET security_inventory=$2,security_at=clock_timestamp() WHERE id=$1`, d.ID, data)
	return err
}
