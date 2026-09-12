CREATE TABLE IF NOT EXISTS uem_access_revisions (
    user_id TEXT PRIMARY KEY REFERENCES users(uid) ON DELETE CASCADE,
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0)
);
CREATE TABLE IF NOT EXISTS uem_access_grants (
    user_id TEXT NOT NULL REFERENCES users(uid) ON DELETE RESTRICT,
    role TEXT NOT NULL CHECK (role IN ('administrator','organization_admin','operator','viewer')),
    tenant_id BIGINT NOT NULL DEFAULT 0 CHECK (tenant_id >= 0),
    site_id BIGINT NOT NULL DEFAULT 0 CHECK (site_id >= 0),
    tenant_ref BIGINT GENERATED ALWAYS AS (NULLIF(tenant_id,0)) STORED REFERENCES tenants(id) ON DELETE RESTRICT,
    site_ref BIGINT GENERATED ALWAYS AS (NULLIF(site_id,0)) STORED REFERENCES sites(id) ON DELETE RESTRICT,
    PRIMARY KEY (user_id,tenant_id,site_id),
    CHECK ((role='administrator' AND tenant_id=0 AND site_id=0)
       OR (role='organization_admin' AND tenant_id>0 AND site_id=0)
       OR (role IN ('operator','viewer') AND tenant_id>0))
);
CREATE INDEX IF NOT EXISTS uem_access_grants_scope ON uem_access_grants(tenant_id,site_id);
CREATE TABLE IF NOT EXISTS uem_access_audit (
    id BIGSERIAL PRIMARY KEY,
    actor TEXT NOT NULL,
    subject TEXT NOT NULL,
    action TEXT NOT NULL,
    before_grants JSONB NOT NULL,
    after_grants JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
