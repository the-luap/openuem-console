CREATE TABLE mdm_windows_syncml_state (
    device_id UUID PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    certificate_id UUID NOT NULL,
    revision BIGINT NOT NULL CHECK (revision>0),
    active_session_id UUID,
    encrypted_state BYTEA NOT NULL CHECK (octet_length(encrypted_state) BETWEEN 30 AND 8221),
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(device_id,tenant_id,site_id),
    UNIQUE(device_id,tenant_id,site_id,certificate_id),
    FOREIGN KEY(device_id,tenant_id,site_id) REFERENCES mdm_windows_devices(id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(certificate_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_device_certificates(id,device_id,tenant_id,site_id) ON DELETE RESTRICT
);

CREATE TABLE mdm_windows_syncml_sessions (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    certificate_id UUID NOT NULL,
    wire_session_id TEXT NOT NULL CHECK (octet_length(wire_session_id) BETWEEN 1 AND 64),
    phase TEXT NOT NULL CHECK (phase IN ('authenticating','active','completed','failed','aborted','expired')),
    revision BIGINT NOT NULL CHECK (revision>0),
    last_message INTEGER NOT NULL CHECK (last_message BETWEEN 1 AND 64),
    encrypted_state BYTEA NOT NULL CHECK (octet_length(encrypted_state) BETWEEN 30 AND 2097181),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at>created_at AND expires_at<=created_at+INTERVAL '15 minutes'),
    UNIQUE(id,device_id,tenant_id,site_id),
    FOREIGN KEY(device_id,tenant_id,site_id,certificate_id) REFERENCES mdm_windows_syncml_state(device_id,tenant_id,site_id,certificate_id) ON DELETE RESTRICT,
    FOREIGN KEY(certificate_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_device_certificates(id,device_id,tenant_id,site_id) ON DELETE RESTRICT
);
ALTER TABLE mdm_windows_syncml_state ADD CONSTRAINT mdm_windows_syncml_active_session_scope
    FOREIGN KEY(active_session_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_syncml_sessions(id,device_id,tenant_id,site_id) ON DELETE RESTRICT;
CREATE INDEX mdm_windows_syncml_sessions_scope ON mdm_windows_syncml_sessions(tenant_id,site_id,created_at DESC,id);

CREATE TABLE mdm_windows_syncml_packets (
    session_id UUID NOT NULL,
    device_id UUID NOT NULL,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    message_id INTEGER NOT NULL CHECK (message_id BETWEEN 1 AND 64),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
    response_digest BYTEA NOT NULL CHECK (octet_length(response_digest)=32),
    encrypted_response BYTEA NOT NULL CHECK (octet_length(encrypted_response) BETWEEN 30 AND 1048605),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(session_id,message_id),
    FOREIGN KEY(session_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_syncml_sessions(id,device_id,tenant_id,site_id) ON DELETE RESTRICT
);

CREATE TABLE mdm_windows_management_audit (
    id BIGSERIAL PRIMARY KEY,
    device_id UUID NOT NULL,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    session_id UUID NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('session.started','session.challenged','session.authenticated','session.completed','session.failed','session.aborted','session.expired','message.replayed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(session_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_syncml_sessions(id,device_id,tenant_id,site_id) ON DELETE RESTRICT
);
CREATE INDEX mdm_windows_management_audit_scope ON mdm_windows_management_audit(tenant_id,site_id,created_at DESC,id);

CREATE FUNCTION mdm_windows_keep_syncml_state() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.device_id,NEW.tenant_id,NEW.site_id,NEW.certificate_id,NEW.created_at)
        IS DISTINCT FROM ROW(OLD.device_id,OLD.tenant_id,OLD.site_id,OLD.certificate_id,OLD.created_at)
        OR NEW.revision<>OLD.revision+1
    THEN RAISE EXCEPTION 'native Windows SyncML state identity and revision are protected'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_windows_syncml_state_identity BEFORE UPDATE OR DELETE ON mdm_windows_syncml_state
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_syncml_state();

CREATE FUNCTION mdm_windows_keep_syncml_session() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.device_id,NEW.tenant_id,NEW.site_id,NEW.certificate_id,NEW.wire_session_id,NEW.created_at,NEW.expires_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.device_id,OLD.tenant_id,OLD.site_id,OLD.certificate_id,OLD.wire_session_id,OLD.created_at,OLD.expires_at)
        OR OLD.phase IN ('completed','failed','aborted','expired')
        OR NEW.revision<>OLD.revision+1
        OR NEW.last_message<OLD.last_message OR NEW.last_message>OLD.last_message+1
        OR (NEW.last_message=OLD.last_message AND NEW.phase<>'expired')
    THEN RAISE EXCEPTION 'native Windows SyncML session identity and progression are protected'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_windows_syncml_session_identity BEFORE UPDATE OR DELETE ON mdm_windows_syncml_sessions
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_syncml_session();

CREATE FUNCTION mdm_windows_keep_management_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'native Windows management history is append only'; END;
$$;
CREATE TRIGGER mdm_windows_syncml_packet_history BEFORE UPDATE OR DELETE ON mdm_windows_syncml_packets
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();
CREATE TRIGGER mdm_windows_management_audit_history BEFORE UPDATE OR DELETE ON mdm_windows_management_audit
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();
