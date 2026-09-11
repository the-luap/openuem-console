-- Legacy inventory is readable even when individual enrollment is disabled.
-- These identifiers deliberately accept non-UUID legacy agent IDs.
CREATE TABLE uem_inventory_audit (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id BIGINT NOT NULL CHECK (tenant_id>0),
 site_id BIGINT NOT NULL CHECK (site_id>0),
 actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 255),
 action TEXT NOT NULL CHECK (action='inventory.desktop.read'),
 resource_id TEXT NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 255),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX uem_inventory_audit_scope ON uem_inventory_audit(tenant_id,created_at DESC,id DESC);
