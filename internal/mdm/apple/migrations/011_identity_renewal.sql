-- Public enrollment metadata is retained independently of browser retry secrets.
CREATE TABLE mdm_apple_enrollment_layouts (
 device_id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 profile_uuid TEXT NOT NULL CHECK (profile_uuid::uuid IS NOT NULL),
 mdm_uuid TEXT NOT NULL CHECK (mdm_uuid::uuid IS NOT NULL),
 identity_uuid TEXT NOT NULL CHECK (identity_uuid::uuid IS NOT NULL),
 ca_uuid TEXT CHECK (ca_uuid IS NULL OR ca_uuid::uuid IS NOT NULL),
 identity_type TEXT NOT NULL CHECK (identity_type IN ('com.apple.security.scep','com.apple.security.pkcs12')),
 public_url TEXT NOT NULL,
 topic TEXT NOT NULL,
 access_rights BIGINT NOT NULL CHECK (access_rights > 0),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 FOREIGN KEY (tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id) ON DELETE CASCADE
);

ALTER TABLE mdm_apple_devices ADD COLUMN next_identity_renewal_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE mdm_apple_devices ADD COLUMN identity_renewal_error TEXT NOT NULL DEFAULT '';
CREATE INDEX mdm_apple_identity_renewal_due ON mdm_apple_devices(next_identity_renewal_at,id) WHERE status='enrolled';
ALTER TABLE mdm_apple_commands ADD CONSTRAINT mdm_apple_command_identity_scope UNIQUE(tenant_id,device_id,id);
ALTER TABLE mdm_apple_commands DROP CONSTRAINT mdm_apple_commands_status_check;
ALTER TABLE mdm_apple_commands ADD CONSTRAINT mdm_apple_commands_status_check CHECK (status IN ('queued','sent','acknowledged','verified','failed','not_now','cancelled','expired'));

CREATE TABLE mdm_apple_identity_renewals (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 command_id UUID NOT NULL UNIQUE,
 authority_id UUID NOT NULL,
 base_fingerprint TEXT NOT NULL CHECK (base_fingerprint ~ '^[0-9a-f]{64}$'),
 base_expires_at TIMESTAMPTZ NOT NULL,
 identity_uuid TEXT NOT NULL CHECK (identity_uuid::uuid IS NOT NULL),
 ca_uuid TEXT NOT NULL CHECK (ca_uuid::uuid IS NOT NULL),
 status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','issued','confirmed','failed','expired','cancelled')),
 challenge_hash TEXT CHECK (challenge_hash ~ '^[0-9a-f]{64}$'),
 expires_at TIMESTAMPTZ NOT NULL,
 csr_hash TEXT CHECK (csr_hash ~ '^[0-9a-f]{64}$'),
 signer_fingerprint TEXT CHECK (signer_fingerprint ~ '^[0-9a-f]{64}$'),
 transaction_id TEXT CHECK (length(transaction_id) BETWEEN 1 AND 128),
 certificate BYTEA,
 certificate_fingerprint TEXT UNIQUE CHECK (certificate_fingerprint ~ '^[0-9a-f]{64}$'),
 certificate_expires_at TIMESTAMPTZ,
 encrypted_token BYTEA,
 encrypted_magic BYTEA,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 issued_at TIMESTAMPTZ,
 token_updated_at TIMESTAMPTZ,
 confirmed_at TIMESTAMPTZ,
 completed_at TIMESTAMPTZ,
 grace_until TIMESTAMPTZ,
 error TEXT NOT NULL DEFAULT '',
 FOREIGN KEY (tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id) ON DELETE CASCADE,
 FOREIGN KEY (tenant_id,device_id,command_id) REFERENCES mdm_apple_commands(tenant_id,device_id,id),
 FOREIGN KEY (tenant_id,authority_id) REFERENCES mdm_apple_scep_authorities(tenant_id,id),
 CHECK (status<>'queued' OR (challenge_hash IS NOT NULL AND certificate IS NULL)),
 CHECK (status NOT IN ('issued','confirmed') OR (challenge_hash IS NULL AND certificate IS NOT NULL AND certificate_fingerprint IS NOT NULL AND certificate_expires_at IS NOT NULL AND issued_at IS NOT NULL)),
 CHECK (status<>'confirmed' OR (confirmed_at IS NOT NULL AND completed_at IS NOT NULL AND token_updated_at IS NOT NULL AND grace_until IS NOT NULL))
);
CREATE UNIQUE INDEX mdm_apple_identity_renewal_active ON mdm_apple_identity_renewals(device_id) WHERE status IN ('queued','issued');
CREATE INDEX mdm_apple_identity_renewal_history ON mdm_apple_identity_renewals(tenant_id,device_id,created_at DESC);
