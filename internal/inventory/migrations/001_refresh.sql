CREATE TABLE uem_inventory_refresh (
 id UUID PRIMARY KEY,
 device_id TEXT NOT NULL CHECK (device_id ~ '^[A-Za-z0-9_-]{1,255}$'),
 tenant_id BIGINT NOT NULL CHECK (tenant_id>0),
 site_id BIGINT NOT NULL CHECK (site_id>0),
 actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 255),
 individual BOOLEAN NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','accepted','stopped','unconfirmed')),
 requested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()+interval '10 minutes',
 next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 finished_at TIMESTAMPTZ,
 CHECK ((status='queued')=(finished_at IS NULL))
);
CREATE UNIQUE INDEX uem_inventory_refresh_pending ON uem_inventory_refresh(device_id) WHERE status='queued';
CREATE INDEX uem_inventory_refresh_due ON uem_inventory_refresh(next_attempt_at,requested_at) WHERE status='queued';
CREATE INDEX uem_inventory_refresh_device ON uem_inventory_refresh(device_id,requested_at DESC,id DESC);

-- Independent committed attempt evidence must survive rollback of the dispatch
-- transaction, including loss of the broker acknowledgement or database commit.
-- No foreign keys: deleting devices/accounts must not erase historical evidence.
CREATE TABLE uem_inventory_refresh_audit (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 request_id UUID NOT NULL,
 tenant_id BIGINT NOT NULL CHECK (tenant_id>0),
 site_id BIGINT NOT NULL CHECK (site_id>0),
 actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 255),
 action TEXT NOT NULL CHECK (action IN ('inventory.refresh.request','inventory.refresh.attempt','inventory.refresh.accepted','inventory.refresh.retry','inventory.refresh.stopped','inventory.refresh.unconfirmed')),
 resource_id TEXT NOT NULL,
 result TEXT NOT NULL CHECK (result IN ('recorded','success','deferred','cancelled','failure')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX uem_inventory_refresh_audit_request ON uem_inventory_refresh_audit(request_id,action);
CREATE INDEX uem_inventory_refresh_audit_scope ON uem_inventory_refresh_audit(tenant_id,created_at DESC,id DESC);
CREATE INDEX uem_inventory_refresh_audit_time ON uem_inventory_refresh_audit(created_at DESC,id DESC);
