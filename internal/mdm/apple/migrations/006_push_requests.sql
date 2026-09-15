ALTER TABLE mdm_apple_settings
 ADD COLUMN push_revision BIGINT NOT NULL DEFAULT 1 CHECK (push_revision > 0),
 ADD COLUMN apple_account TEXT NOT NULL DEFAULT '';

CREATE TABLE mdm_apple_push_requests (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
 organization TEXT NOT NULL,
 public_url TEXT NOT NULL,
 apple_account TEXT NOT NULL,
 expected_topic TEXT NOT NULL,
 base_revision BIGINT NOT NULL CHECK (base_revision >= 0),
 csr BYTEA NOT NULL,
 encrypted_key BYTEA,
 status TEXT NOT NULL DEFAULT 'pending'
  CHECK (status IN ('pending','imported','revoked','expired','superseded')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()+interval '7 days',
 completed_at TIMESTAMPTZ,
 CHECK ((status='pending' AND encrypted_key IS NOT NULL AND completed_at IS NULL)
     OR (status<>'pending' AND encrypted_key IS NULL AND completed_at IS NOT NULL)),
 UNIQUE (tenant_id,id)
);
CREATE INDEX mdm_apple_push_requests_pending ON mdm_apple_push_requests(tenant_id,expires_at)
 WHERE status='pending';
