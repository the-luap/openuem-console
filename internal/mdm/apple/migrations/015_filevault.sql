-- Recovery material outlives enrollment: profile removal and CheckOut do not
-- decrypt a FileVault volume. Deliberately do not cascade-delete these records.
ALTER TABLE mdm_apple_commands ADD COLUMN filevault BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE mdm_apple_filevault_escrow (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 certificate BYTEA NOT NULL,
 private_key BYTEA NOT NULL,
 enable_uuid UUID NOT NULL UNIQUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,device_id,id),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES mdm_apple_devices(tenant_id,site_id,id)
);

CREATE TABLE mdm_apple_filevault_keys (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 escrow_id UUID NOT NULL,
 recovery_key BYTEA NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 verified_at TIMESTAMPTZ,
 UNIQUE(tenant_id,device_id,id),
 FOREIGN KEY(tenant_id,device_id,escrow_id) REFERENCES mdm_apple_filevault_escrow(tenant_id,device_id,id)
);
CREATE INDEX mdm_apple_filevault_key_history ON mdm_apple_filevault_keys(device_id,created_at DESC);

CREATE TABLE mdm_apple_filevault_policies (
 device_id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 escrow_id UUID NOT NULL,
 desired TEXT NOT NULL CHECK(desired IN ('enabled','removed')),
 phase TEXT NOT NULL CHECK(phase IN ('preflight','installing_escrow','verifying_escrow','installing_enable','verifying_enable','active','removing_enable','verifying_enable_removal','removing_escrow','verifying_removal','removed','failed','not_managed')),
 command_id UUID UNIQUE,
 error TEXT NOT NULL DEFAULT '',
 recovery_error TEXT NOT NULL DEFAULT '',
 current_key_id UUID,
 recovery_requested_at TIMESTAMPTZ,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES mdm_apple_devices(tenant_id,site_id,id),
 FOREIGN KEY(tenant_id,device_id,escrow_id) REFERENCES mdm_apple_filevault_escrow(tenant_id,device_id,id),
 FOREIGN KEY(tenant_id,device_id,current_key_id) REFERENCES mdm_apple_filevault_keys(tenant_id,device_id,id),
 FOREIGN KEY(tenant_id,device_id,command_id) REFERENCES mdm_apple_commands(tenant_id,device_id,id)
);
