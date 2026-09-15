-- A device reports the start of disconnection, not verified local cleanup.
-- The same transaction retires server access and retains interrupted work.
CREATE TABLE mdm_windows_unenrollment_reports (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL UNIQUE,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    certificate_id UUID NOT NULL,
    anchor_certificate_id UUID NOT NULL,
    fingerprint BYTEA NOT NULL CHECK (octet_length(fingerprint)=32),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
    response_digest BYTEA NOT NULL CHECK (octet_length(response_digest)=32),
    interrupted_session_id UUID,
    encrypted_record BYTEA NOT NULL CHECK (octet_length(encrypted_record) BETWEEN 30 AND 2097181),
    received_at TIMESTAMPTZ NOT NULL,
    UNIQUE(id,device_id,tenant_id,site_id),
    FOREIGN KEY(device_id,tenant_id,site_id) REFERENCES mdm_windows_devices(id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(certificate_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_device_certificates(id,device_id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(anchor_certificate_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_device_certificates(id,device_id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(interrupted_session_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_syncml_sessions(id,device_id,tenant_id,site_id) ON DELETE RESTRICT
);
CREATE INDEX mdm_windows_unenrollment_reports_scope ON mdm_windows_unenrollment_reports(tenant_id,site_id,received_at DESC,id);
CREATE TABLE mdm_windows_unenrollment_audit (
    id BIGSERIAL PRIMARY KEY,
    report_id UUID NOT NULL,
    device_id UUID NOT NULL,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    actor TEXT NOT NULL CHECK (octet_length(actor) BETWEEN 1 AND 255),
    action TEXT NOT NULL CHECK (action IN ('unenrollment.reported','unenrollment.read')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(report_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_unenrollment_reports(id,device_id,tenant_id,site_id) ON DELETE RESTRICT
);
CREATE INDEX mdm_windows_unenrollment_audit_scope ON mdm_windows_unenrollment_audit(tenant_id,site_id,id DESC);
CREATE TRIGGER mdm_windows_unenrollment_report_history BEFORE UPDATE OR DELETE ON mdm_windows_unenrollment_reports
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();
CREATE TRIGGER mdm_windows_unenrollment_audit_history BEFORE UPDATE OR DELETE ON mdm_windows_unenrollment_audit
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();

-- An authenticated disconnection notification can terminate a live session
-- without pretending that another packet was received in that old session.
CREATE OR REPLACE FUNCTION mdm_windows_keep_syncml_session() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.device_id,NEW.tenant_id,NEW.site_id,NEW.certificate_id,NEW.wire_session_id,NEW.created_at,NEW.expires_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.device_id,OLD.tenant_id,OLD.site_id,OLD.certificate_id,OLD.wire_session_id,OLD.created_at,OLD.expires_at)
        OR OLD.phase IN ('completed','failed','aborted','expired')
        OR NEW.revision<>OLD.revision+1
        OR NEW.last_message<OLD.last_message OR NEW.last_message>OLD.last_message+1
        OR (NEW.last_message=OLD.last_message AND NEW.phase NOT IN ('expired','aborted'))
    THEN RAISE EXCEPTION 'native Windows SyncML session identity and progression are protected'; END IF;
    RETURN NEW;
END;
$$;
