-- Registration authorities protect the issuing CA from CMS decryption. Keep
-- each public authority stable for every outstanding enrollment using its key.
CREATE TABLE mdm_apple_scep_authorities (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES mdm_apple_settings(tenant_id) ON DELETE CASCADE,
 certificate BYTEA NOT NULL,
 encrypted_key BYTEA NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE (tenant_id,id)
);
CREATE INDEX mdm_apple_scep_authority_expiry ON mdm_apple_scep_authorities(tenant_id,expires_at DESC);

CREATE TABLE mdm_apple_scep_enrollments (
 device_id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 authority_id UUID NOT NULL,
 challenge_hash TEXT CHECK (challenge_hash ~ '^[0-9a-f]{64}$'),
 expires_at TIMESTAMPTZ NOT NULL,
 csr_hash TEXT CHECK (csr_hash ~ '^[0-9a-f]{64}$'),
 signer_fingerprint TEXT CHECK (signer_fingerprint ~ '^[0-9a-f]{64}$'),
 transaction_id TEXT CHECK (length(transaction_id) BETWEEN 1 AND 128),
 certificate BYTEA,
 issued_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 FOREIGN KEY (tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id) ON DELETE CASCADE,
 FOREIGN KEY (tenant_id,authority_id) REFERENCES mdm_apple_scep_authorities(tenant_id,id),
 CHECK ((issued_at IS NULL AND csr_hash IS NULL AND signer_fingerprint IS NULL AND transaction_id IS NULL AND certificate IS NULL)
     OR (issued_at IS NOT NULL AND csr_hash IS NOT NULL AND signer_fingerprint IS NOT NULL AND transaction_id IS NOT NULL AND certificate IS NOT NULL AND challenge_hash IS NULL))
);
CREATE INDEX mdm_apple_scep_enrollment_expiry ON mdm_apple_scep_enrollments(expires_at) WHERE challenge_hash IS NOT NULL;
