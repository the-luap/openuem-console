CREATE TABLE uem_audit_activity (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id BIGINT NOT NULL DEFAULT 0 CHECK (tenant_id>=0),
 site_id BIGINT NOT NULL DEFAULT 0 CHECK (site_id>=0),
 actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 255),
 action TEXT NOT NULL CHECK (action IN ('audit.view','audit.export')),
 resource_id TEXT NOT NULL CHECK (resource_id ~ '^[0-9a-f]{64}$'),
 result TEXT NOT NULL CHECK (result IN ('success','failure','denied')),
 event_count INTEGER NOT NULL CHECK (event_count BETWEEN 0 AND 10000),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK (tenant_id>0 OR site_id=0)
);
CREATE INDEX uem_audit_activity_scope ON uem_audit_activity(tenant_id,created_at DESC,id DESC);
CREATE INDEX uem_audit_activity_time ON uem_audit_activity(created_at DESC,id DESC);

-- Zero means retain indefinitely. No historical events are deleted on upgrade.
CREATE TABLE uem_audit_retention (
 tenant_id BIGINT PRIMARY KEY CHECK (tenant_id>=0),
 days INTEGER NOT NULL DEFAULT 0 CHECK (days=0 OR days BETWEEN 30 AND 3650),
 revision BIGINT NOT NULL DEFAULT 1 CHECK (revision>0),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_by TEXT NOT NULL,
 next_sweep_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX uem_audit_retention_due ON uem_audit_retention(next_sweep_at,tenant_id) WHERE days>0;

-- Policy and erasure history is deliberately retained independently of events.
CREATE TABLE uem_audit_retention_history (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id BIGINT NOT NULL CHECK (tenant_id>=0),
 actor TEXT NOT NULL,
 action TEXT NOT NULL CHECK (action IN ('retention.change','retention.prune')),
 previous_days INTEGER,
 days INTEGER NOT NULL,
 revision BIGINT NOT NULL,
 source TEXT NOT NULL DEFAULT '',
 cutoff TIMESTAMPTZ,
 event_count INTEGER NOT NULL DEFAULT 0 CHECK (event_count>=0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX uem_audit_retention_history_scope ON uem_audit_retention_history(tenant_id,created_at DESC,id DESC);

CREATE TABLE uem_audit_retention_previews (
 id UUID PRIMARY KEY,
 token_hash TEXT NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
 actor TEXT NOT NULL,
 tenant_id BIGINT NOT NULL CHECK (tenant_id>=0),
 days INTEGER NOT NULL CHECK (days=0 OR days BETWEEN 30 AND 3650),
 revision BIGINT NOT NULL CHECK (revision>=0),
 cutoff TIMESTAMPTZ,
 counts JSONB NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()+interval '10 minutes'
);
CREATE INDEX uem_audit_retention_previews_expiry ON uem_audit_retention_previews(expires_at);
CREATE INDEX uem_audit_retention_previews_actor_scope ON uem_audit_retention_previews(actor,tenant_id);
