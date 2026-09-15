-- Association challenges are native MDM resources, even when no agent registry
-- is configured. Cross-channel foreign keys are added by optional link setup.
ALTER TABLE mdm_apple_devices ADD CONSTRAINT mdm_apple_device_channel_scope UNIQUE(tenant_id,site_id,id);
ALTER TABLE mdm_apple_commands ADD CONSTRAINT mdm_apple_command_channel_scope UNIQUE(tenant_id,device_id,id);
ALTER TABLE mdm_apple_commands ADD COLUMN mac_binding BOOLEAN NOT NULL DEFAULT false;
CREATE TABLE mdm_apple_mac_bindings (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 command_id UUID NOT NULL UNIQUE,
 profile_identifier TEXT NOT NULL UNIQUE,
 profile_uuid UUID NOT NULL UNIQUE,
 token_hash TEXT NOT NULL CHECK(token_hash ~ '^[a-f0-9]{64}$'),
 status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','installed','consumed','expired','cancelled','failed','conflict')),
 agent_id UUID,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL,
 installed_at TIMESTAMPTZ,
 completed_at TIMESTAMPTZ,
 cleanup_command_id UUID UNIQUE,
 cleanup_at TIMESTAMPTZ,
 cleanup_attempts INTEGER NOT NULL DEFAULT 0 CHECK(cleanup_attempts BETWEEN 0 AND 5),
 next_cleanup_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES mdm_apple_devices(tenant_id,site_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,device_id,command_id) REFERENCES mdm_apple_commands(tenant_id,device_id,id),
 FOREIGN KEY(tenant_id,device_id,cleanup_command_id) REFERENCES mdm_apple_commands(tenant_id,device_id,id),
 CHECK(status <> 'consumed' OR agent_id IS NOT NULL)
);
CREATE UNIQUE INDEX mdm_apple_mac_binding_active ON mdm_apple_mac_bindings(device_id) WHERE status IN ('queued','installed');
CREATE INDEX mdm_apple_mac_binding_cleanup ON mdm_apple_mac_bindings(next_cleanup_at,device_id) WHERE cleanup_at IS NULL;
