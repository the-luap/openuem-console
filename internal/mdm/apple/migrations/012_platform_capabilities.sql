-- Keep the platform and the hardware evidence in the same persisted row.
-- Unknown model data never grants iOS or macOS capabilities.
ALTER TABLE mdm_apple_devices ADD COLUMN platform TEXT GENERATED ALWAYS AS (
 CASE
  WHEN model ~ '^iPad([0-9]+,[0-9]+)?$' THEN 'ipados'
  WHEN model ~ '^(iPhone|iPod)([0-9]+,[0-9]+)?$' THEN 'ios'
  WHEN model ~ '^(Mac|MacBookPro|MacBookAir|MacBook|Macmini|MacPro|MacStudio|iMac|iMacPro|Xserve)([0-9]+,[0-9]+)?$'
    OR model IN ('MacBook Pro','MacBook Air','Mac mini','Mac Pro','Mac Studio','iMac Pro') THEN 'macos'
  ELSE 'unknown'
 END
) STORED;
ALTER TABLE mdm_apple_devices ADD COLUMN enrollment_method TEXT NOT NULL DEFAULT 'manual_device'
 CHECK (enrollment_method IN ('manual_device'));
ALTER TABLE mdm_apple_devices ADD COLUMN enrollment_platform TEXT NOT NULL DEFAULT ''
 CHECK (enrollment_platform IN ('','ios','ipados','macos'));
ALTER TABLE mdm_apple_devices ADD COLUMN supervised_reported BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE mdm_apple_devices ADD COLUMN software_update_device_id TEXT NOT NULL DEFAULT '';
ALTER TABLE mdm_apple_devices ADD COLUMN apple_silicon BOOLEAN;
ALTER TABLE mdm_apple_devices ADD COLUMN security_inventory JSONB NOT NULL DEFAULT '{}';
ALTER TABLE mdm_apple_devices ADD COLUMN security_at TIMESTAMPTZ;
-- Existing boolean evidence can be recovered only if inventory contains it.
UPDATE mdm_apple_devices SET supervised_reported=true,supervised=(inventory->>'IsSupervised')::boolean
 WHERE jsonb_typeof(inventory->'IsSupervised')='boolean';
CREATE INDEX mdm_apple_devices_platform_scope ON mdm_apple_devices(tenant_id,platform,site_id);

CREATE TABLE mdm_apple_bootstrap_tokens (
 device_id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES mdm_apple_settings(tenant_id),
 encrypted_token BYTEA NOT NULL CHECK (octet_length(encrypted_token)>0),
 token_hash TEXT NOT NULL CHECK (token_hash ~ '^[a-f0-9]{64}$'),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY (tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id)
);
-- Enrollment replacement retains the advertised capability across key rotation.
ALTER TABLE mdm_apple_enrollment_layouts ADD COLUMN bootstrap_token BOOLEAN NOT NULL DEFAULT false;
