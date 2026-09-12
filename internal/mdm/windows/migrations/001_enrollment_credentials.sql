CREATE TABLE mdm_windows_invitations (
    id UUID PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    username TEXT NOT NULL CHECK (octet_length(username) BETWEEN 1 AND 320),
    credential_digest BYTEA NOT NULL CHECK (octet_length(credential_digest)=32),
    created_by TEXT NOT NULL CHECK (octet_length(created_by) BETWEEN 1 AND 255),
    created_by_revision INTEGER NOT NULL CHECK (created_by_revision>0),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    CHECK (expires_at>created_at AND expires_at<=created_at+INTERVAL '86400 seconds'),
    CHECK (revoked_at IS NULL OR revoked_at>=created_at),
    CHECK (consumed_at IS NULL OR (consumed_at>=created_at AND consumed_at<expires_at))
);
CREATE INDEX mdm_windows_invitations_scope ON mdm_windows_invitations(tenant_id,site_id,created_at DESC,id);

-- Credentials cannot be reassigned, extended or rearmed. Preserve the original
-- issuer and timestamps so old credentials never gain a new meaning.
CREATE FUNCTION mdm_windows_keep_invitation_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id,NEW.tenant_id,NEW.site_id,NEW.username,NEW.credential_digest,NEW.created_by,NEW.created_by_revision,NEW.created_at,NEW.expires_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.site_id,OLD.username,OLD.credential_digest,OLD.created_by,OLD.created_by_revision,OLD.created_at,OLD.expires_at)
        OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
        OR (OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at)
    THEN
        RAISE EXCEPTION 'native Windows enrollment invitation identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_windows_invitation_identity BEFORE UPDATE ON mdm_windows_invitations
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_invitation_identity();

CREATE TABLE mdm_windows_audit (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    actor TEXT NOT NULL CHECK (octet_length(actor) BETWEEN 1 AND 255),
    action TEXT NOT NULL CHECK (action IN ('invitation.created','invitation.read','invitation.revoked','invitation.consumed')),
    resource_id UUID NOT NULL REFERENCES mdm_windows_invitations(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX mdm_windows_audit_scope ON mdm_windows_audit(tenant_id,site_id,id DESC);
