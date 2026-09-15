CREATE TABLE mdm_windows_authorities (
    id UUID PRIMARY KEY,
    tenant_id BIGINT NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE RESTRICT,
    organization TEXT NOT NULL CHECK (octet_length(organization) BETWEEN 1 AND 128),
    minimum_key_bits INTEGER NOT NULL CHECK (minimum_key_bits IN (2048,3072,4096)),
    validity_seconds BIGINT NOT NULL CHECK (validity_seconds BETWEEN 86400 AND 31536000),
    renewal_seconds BIGINT NOT NULL CHECK (renewal_seconds>=3600 AND renewal_seconds<validity_seconds),
    certificate BYTEA NOT NULL CHECK (octet_length(certificate) BETWEEN 1 AND 16384),
    encrypted_key BYTEA NOT NULL CHECK (octet_length(encrypted_key) BETWEEN 30 AND 8221),
    created_by TEXT NOT NULL CHECK (octet_length(created_by) BETWEEN 1 AND 255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at>created_at),
    UNIQUE(id,tenant_id)
);

CREATE FUNCTION mdm_windows_keep_authority_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'native Windows enrollment authority is immutable';
END;
$$;
CREATE TRIGGER mdm_windows_authority_identity BEFORE UPDATE OR DELETE ON mdm_windows_authorities
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_authority_identity();

CREATE TABLE mdm_windows_authority_audit (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    actor TEXT NOT NULL CHECK (octet_length(actor) BETWEEN 1 AND 255),
    action TEXT NOT NULL CHECK (action IN ('authority.created','authority.read')),
    authority_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(authority_id,tenant_id) REFERENCES mdm_windows_authorities(id,tenant_id) ON DELETE RESTRICT
);
CREATE INDEX mdm_windows_authority_audit_scope ON mdm_windows_authority_audit(tenant_id,id DESC);

ALTER TABLE mdm_windows_audit DROP CONSTRAINT mdm_windows_audit_action_check;
ALTER TABLE mdm_windows_audit ADD CONSTRAINT mdm_windows_audit_action_check
    CHECK (action IN ('invitation.created','invitation.read','invitation.revoked','invitation.consumed','policy.read'));
