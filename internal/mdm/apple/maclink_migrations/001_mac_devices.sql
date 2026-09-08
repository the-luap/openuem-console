-- Initialized only after both native Apple and individual agent migrations.
CREATE TABLE uem_mac_devices (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 model TEXT NOT NULL,
 serial TEXT NOT NULL,
 platform_uuid TEXT NOT NULL,
 provisioning_udid TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,site_id,id)
);
CREATE UNIQUE INDEX uem_mac_hardware_anchor ON uem_mac_devices(tenant_id,site_id,platform_uuid);
CREATE TABLE uem_mac_mdm_channels (
 device_id UUID PRIMARY KEY,
 entity_id UUID NOT NULL,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 attached_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 retired_at TIMESTAMPTZ,
 FOREIGN KEY(tenant_id,site_id,entity_id) REFERENCES uem_mac_devices(tenant_id,site_id,id),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES mdm_apple_devices(tenant_id,site_id,id)
);
CREATE UNIQUE INDEX uem_mac_active_mdm ON uem_mac_mdm_channels(entity_id) WHERE retired_at IS NULL;
CREATE TABLE uem_mac_agent_channels (
 device_id UUID PRIMARY KEY,
 entity_id UUID NOT NULL,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 attached_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 retired_at TIMESTAMPTZ,
 FOREIGN KEY(tenant_id,site_id,entity_id) REFERENCES uem_mac_devices(tenant_id,site_id,id),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES uem_agent_identities(tenant_id,site_id,id)
);
CREATE UNIQUE INDEX uem_mac_active_agent ON uem_mac_agent_channels(entity_id) WHERE retired_at IS NULL;
ALTER TABLE mdm_apple_mac_bindings ADD CONSTRAINT mdm_apple_mac_binding_agent_scope FOREIGN KEY(tenant_id,site_id,agent_id) REFERENCES uem_agent_identities(tenant_id,site_id,id);
