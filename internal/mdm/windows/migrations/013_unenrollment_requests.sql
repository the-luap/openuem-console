CREATE TABLE mdm_windows_unenrollment_requests (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    request_key UUID NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(uid) ON DELETE RESTRICT,
    created_by_revision BIGINT NOT NULL CHECK (created_by_revision>0),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at>=created_at+INTERVAL '1 minute' AND expires_at<=created_at+INTERVAL '7 days'),
    encrypted_intent BYTEA NOT NULL CHECK (octet_length(encrypted_intent) BETWEEN 30 AND 8221),
    UNIQUE(device_id,request_key),
    UNIQUE(id,device_id,tenant_id,site_id,request_key,created_by,created_by_revision,created_at,expires_at),
    FOREIGN KEY(device_id,tenant_id,site_id) REFERENCES mdm_windows_devices(id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(id,device_id,tenant_id,site_id) REFERENCES mdm_windows_csp_commands(id,device_id,tenant_id,site_id) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE mdm_windows_csp_commands ADD COLUMN unenrollment_request_id UUID UNIQUE;
ALTER TABLE mdm_windows_csp_commands ADD CONSTRAINT mdm_windows_csp_unenrollment_shape
    CHECK (unenrollment_request_id IS NULL OR (unenrollment_request_id=id AND update_run_id IS NULL AND NOT user_target));
ALTER TABLE mdm_windows_csp_commands ADD CONSTRAINT mdm_windows_csp_unenrollment_request
    FOREIGN KEY(unenrollment_request_id,device_id,tenant_id,site_id,request_key,created_by,created_by_revision,created_at,expires_at)
    REFERENCES mdm_windows_unenrollment_requests(id,device_id,tenant_id,site_id,request_key,created_by,created_by_revision,created_at,expires_at) ON DELETE RESTRICT;
CREATE INDEX mdm_windows_unenrollment_requests_scope ON mdm_windows_unenrollment_requests(tenant_id,site_id,created_at DESC,id);
CREATE TABLE mdm_windows_unenrollment_releases (
    request_id UUID PRIMARY KEY REFERENCES mdm_windows_unenrollment_requests(id) ON DELETE RESTRICT,
    released_by TEXT NOT NULL REFERENCES users(uid) ON DELETE RESTRICT,
    released_revision BIGINT NOT NULL CHECK (released_revision>0),
    released_at TIMESTAMPTZ NOT NULL,
    encrypted_reason BYTEA NOT NULL CHECK (octet_length(encrypted_reason) BETWEEN 30 AND 8221)
);
CREATE TABLE mdm_windows_unenrollment_request_audit (
    id BIGSERIAL PRIMARY KEY,
    request_id UUID NOT NULL REFERENCES mdm_windows_unenrollment_requests(id) ON DELETE RESTRICT,
    actor TEXT NOT NULL CHECK (octet_length(actor) BETWEEN 1 AND 255),
    action TEXT NOT NULL CHECK (action IN ('request.created','request.replayed','request.read','request.canceled','request.released')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER mdm_windows_unenrollment_request_history BEFORE UPDATE OR DELETE ON mdm_windows_unenrollment_requests
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();
CREATE TRIGGER mdm_windows_unenrollment_release_history BEFORE UPDATE OR DELETE ON mdm_windows_unenrollment_releases
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();
CREATE TRIGGER mdm_windows_unenrollment_request_audit_history BEFORE UPDATE OR DELETE ON mdm_windows_unenrollment_request_audit
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();

-- Extend the immutable command owner without changing old request ciphertext.
CREATE OR REPLACE FUNCTION mdm_windows_keep_csp_command() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.device_id,NEW.tenant_id,NEW.site_id,NEW.request_key,NEW.request_digest,NEW.created_by,NEW.created_by_revision,NEW.user_target,NEW.encrypted_request,NEW.created_at,NEW.expires_at,NEW.update_run_id,NEW.update_step,NEW.unenrollment_request_id)
        IS DISTINCT FROM ROW(OLD.id,OLD.device_id,OLD.tenant_id,OLD.site_id,OLD.request_key,OLD.request_digest,OLD.created_by,OLD.created_by_revision,OLD.user_target,OLD.encrypted_request,OLD.created_at,OLD.expires_at,OLD.update_run_id,OLD.update_step,OLD.unenrollment_request_id)
        OR NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at
        OR OLD.phase IN ('acknowledged','failed','abandoned','canceled','expired')
        OR (OLD.phase IN ('queued','blocked') AND NEW.phase NOT IN ('queued','blocked','sent','canceled','expired'))
        OR (OLD.delivered_session_id IS NOT NULL AND ROW(NEW.delivered_session_id,NEW.delivered_message,NEW.delivered_at) IS DISTINCT FROM ROW(OLD.delivered_session_id,OLD.delivered_message,OLD.delivered_at))
        OR (OLD.phase='sent' AND NEW.phase NOT IN ('sent','acknowledged','failed','unknown'))
        OR (OLD.phase='unknown' AND NEW.phase NOT IN ('unknown','acknowledged','failed','abandoned'))
    THEN RAISE EXCEPTION 'native Windows CSP command identity and progression are protected'; END IF;
    RETURN NEW;
END;
$$;
