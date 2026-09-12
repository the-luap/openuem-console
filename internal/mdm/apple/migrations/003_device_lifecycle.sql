ALTER TABLE mdm_apple_devices DROP CONSTRAINT IF EXISTS mdm_apple_devices_tenant_id_udid_key;
CREATE UNIQUE INDEX IF NOT EXISTS mdm_apple_devices_active_udid ON mdm_apple_devices(tenant_id,udid)
 WHERE udid IS NOT NULL AND status IN ('authenticating','enrolled');
ALTER TABLE mdm_apple_devices ADD COLUMN IF NOT EXISTS next_inventory_at TIMESTAMPTZ NOT NULL DEFAULT now();
