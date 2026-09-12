-- Independent console expectations for private agent receipts. These records
-- also exist in native-only installations; agent tables are optional there.
CREATE TABLE mdm_apple_filevault_validations (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 key_id UUID NOT NULL,
 entity_id UUID NOT NULL,
 agent_id UUID NOT NULL,
 recipient_id UUID NOT NULL,
 certificate_hash TEXT NOT NULL CHECK(certificate_hash ~ '^[a-f0-9]{64}$'),
 nonce_hash TEXT NOT NULL CHECK(nonce_hash ~ '^[a-f0-9]{64}$'),
 actor TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','valid','invalid','unavailable','unsupported','expired','cancelled','superseded','rejected')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL,
 completed_at TIMESTAMPTZ,
 next_check_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES mdm_apple_devices(tenant_id,site_id,id),
 FOREIGN KEY(tenant_id,device_id,key_id) REFERENCES mdm_apple_filevault_keys(tenant_id,device_id,id)
);
CREATE UNIQUE INDEX mdm_apple_filevault_validation_pending ON mdm_apple_filevault_validations(device_id) WHERE status='queued';
CREATE INDEX mdm_apple_filevault_validation_history ON mdm_apple_filevault_validations(device_id,key_id,created_at DESC,id DESC);
CREATE INDEX mdm_apple_filevault_validation_check ON mdm_apple_filevault_validations(next_check_at,id) WHERE status='queued';
