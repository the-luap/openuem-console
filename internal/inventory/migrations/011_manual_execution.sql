CREATE TABLE uem_manual_execution (
 id UUID PRIMARY KEY,
 device_id TEXT NOT NULL CHECK (device_id ~ '^[A-Za-z0-9_-]{1,255}$'),
 tenant_id BIGINT NOT NULL CHECK (tenant_id>0),
 site_id BIGINT NOT NULL CHECK (site_id>0),
 actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 255),
 individual BOOLEAN NOT NULL,
 kind TEXT NOT NULL CHECK (kind IN ('task','profile')),
 source_id BIGINT NOT NULL CHECK (source_id>0),
 profile_id BIGINT NOT NULL CHECK (profile_id>0),
 source_tenant_id BIGINT NOT NULL CHECK (source_tenant_id>=0),
 source_site_id BIGINT NOT NULL CHECK (source_site_id>=0),
 revision TEXT NOT NULL CHECK (revision ~ '^[0-9a-f]{64}$'),
 status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','accepted','rejected','stopped','unconfirmed')),
 reason TEXT NOT NULL DEFAULT '' CHECK (reason IN ('','expired','mode_changed','not_authorized','target_changed','source_changed','configuration_unavailable','agent_rejected','delivery_unconfirmed')),
 requested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()+interval '2 minutes',
 finished_at TIMESTAMPTZ,
 CHECK ((source_tenant_id=0 AND source_site_id=0) OR (source_tenant_id=tenant_id AND source_site_id IN (0,site_id))),
 CHECK (kind<>'profile' OR source_id=profile_id),
 CHECK ((status='queued')=(finished_at IS NULL))
);
CREATE UNIQUE INDEX uem_manual_execution_pending ON uem_manual_execution(device_id) WHERE status='queued';
CREATE INDEX uem_manual_execution_due ON uem_manual_execution(requested_at,id) WHERE status='queued';
CREATE INDEX uem_manual_execution_device ON uem_manual_execution(device_id,requested_at DESC,id DESC);

-- Independent attempt evidence survives request-transaction rollback, loss of
-- acknowledgement and object deletion. It must not block on a request-row FK.
CREATE TABLE uem_manual_execution_audit (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 request_id UUID NOT NULL,
 tenant_id BIGINT NOT NULL CHECK (tenant_id>0),
 site_id BIGINT NOT NULL CHECK (site_id>0),
 actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 255),
 action TEXT NOT NULL CHECK (action IN ('inventory.execution.request','inventory.execution.attempt','inventory.execution.accepted','inventory.execution.rejected','inventory.execution.stopped','inventory.execution.unconfirmed')),
 resource_id TEXT NOT NULL,
 result TEXT NOT NULL CHECK (result IN ('recorded','success','cancelled','failure')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX uem_manual_execution_one_attempt ON uem_manual_execution_audit(request_id) WHERE action='inventory.execution.attempt';
CREATE INDEX uem_manual_execution_audit_request ON uem_manual_execution_audit(request_id,id);
CREATE INDEX uem_manual_execution_audit_scope ON uem_manual_execution_audit(tenant_id,created_at DESC,id DESC);
CREATE INDEX uem_manual_execution_audit_time ON uem_manual_execution_audit(created_at DESC,id DESC);
