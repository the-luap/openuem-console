-- ADE server authority is separate from APNs and from native device enrollment.
-- A synchronized assignment is not proof that a device enrolled in this service.
CREATE TABLE mdm_apple_ade_servers (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES tenants(id),
 name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 255),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','connected','disabled')),
 certificate BYTEA NOT NULL,
 private_key BYTEA NOT NULL,
 certificate_expires_at TIMESTAMPTZ NOT NULL,
 token BYTEA,
 token_hash TEXT NOT NULL DEFAULT '',
 token_revision BIGINT NOT NULL DEFAULT 0,
 token_expires_at TIMESTAMPTZ,
 apple_server_id UUID UNIQUE,
 apple_server_name TEXT NOT NULL DEFAULT '',
 apple_organization_id TEXT NOT NULL DEFAULT '',
 apple_organization_name TEXT NOT NULL DEFAULT '',
 apple_administrator TEXT NOT NULL DEFAULT '',
 verified_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 sync_mode TEXT NOT NULL DEFAULT 'full' CHECK(sync_mode IN ('full','delta')),
 sync_generation UUID NOT NULL DEFAULT gen_random_uuid(),
 sync_cursor TEXT NOT NULL DEFAULT '' CHECK(octet_length(sync_cursor)<=1000),
 cursor_updated_at TIMESTAMPTZ,
 page_count BIGINT NOT NULL DEFAULT 0,
 synced_at TIMESTAMPTZ,
 attempted_at TIMESTAMPTZ,
 next_sync_at TIMESTAMPTZ,
 retry_after TIMESTAMPTZ,
 sync_error TEXT NOT NULL DEFAULT '',
 UNIQUE(tenant_id,id),
 CHECK(status<>'connected' OR (token IS NOT NULL AND token_expires_at IS NOT NULL AND apple_server_id IS NOT NULL AND apple_organization_id<>''))
);
CREATE INDEX mdm_apple_ade_due ON mdm_apple_ade_servers(next_sync_at,id) WHERE status='connected';

CREATE TABLE mdm_apple_ade_devices (
 tenant_id BIGINT NOT NULL,
 server_id UUID NOT NULL,
 serial TEXT NOT NULL CHECK(serial ~ '^[A-Z0-9]{1,64}$'),
 assigned BOOLEAN NOT NULL,
 payload JSONB NOT NULL CHECK(jsonb_typeof(payload)='object'),
 operation_at TIMESTAMPTZ,
 observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,server_id,serial),
 FOREIGN KEY(tenant_id,server_id) REFERENCES mdm_apple_ade_servers(tenant_id,id)
);

-- Initial/restarted full fetches are published only after the last page. A failed
-- or incomplete fetch must never remove assignments from the published snapshot.
CREATE TABLE mdm_apple_ade_fetch (
 tenant_id BIGINT NOT NULL,
 server_id UUID NOT NULL,
 generation UUID NOT NULL,
 serial TEXT NOT NULL CHECK(serial ~ '^[A-Z0-9]{1,64}$'),
 payload JSONB NOT NULL CHECK(jsonb_typeof(payload)='object'),
 PRIMARY KEY(tenant_id,server_id,generation,serial),
 FOREIGN KEY(tenant_id,server_id) REFERENCES mdm_apple_ade_servers(tenant_id,id)
);
CREATE TABLE mdm_apple_ade_cursors (
 server_id UUID NOT NULL REFERENCES mdm_apple_ade_servers(id),
 generation UUID NOT NULL,
 cursor_hash TEXT NOT NULL CHECK(cursor_hash ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(server_id,generation,cursor_hash)
);
