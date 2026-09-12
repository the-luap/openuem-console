CREATE TABLE mdm_windows_console_audit (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    site_id BIGINT NOT NULL CHECK (site_id>=0),
    site_ref BIGINT GENERATED ALWAYS AS (NULLIF(site_id,0)) STORED REFERENCES sites(id) ON DELETE RESTRICT,
    actor TEXT NOT NULL CHECK (octet_length(actor) BETWEEN 1 AND 255),
    action TEXT NOT NULL CHECK (action IN ('invitations.list','devices.list','device.read','device.revoked','authority.status')),
    resource_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((action IN ('device.read','device.revoked')) = (resource_id IS NOT NULL))
);
CREATE INDEX mdm_windows_console_audit_scope ON mdm_windows_console_audit(tenant_id,site_id,id DESC);

CREATE FUNCTION mdm_windows_keep_console_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'native Windows console audit is append-only';
END $$;
CREATE TRIGGER mdm_windows_console_audit_immutable BEFORE UPDATE OR DELETE ON mdm_windows_console_audit
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_console_audit();
