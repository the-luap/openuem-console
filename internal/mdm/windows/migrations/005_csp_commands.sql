CREATE TABLE mdm_windows_csp_commands (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    request_key UUID NOT NULL,
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
    created_by TEXT NOT NULL REFERENCES users(uid) ON DELETE RESTRICT,
    created_by_revision BIGINT NOT NULL CHECK (created_by_revision>0),
    user_target BOOLEAN NOT NULL,
    revision BIGINT NOT NULL CHECK (revision>0),
    phase TEXT NOT NULL CHECK (phase IN ('queued','blocked','sent','acknowledged','failed','unknown','abandoned','canceled','expired')),
    encrypted_request BYTEA NOT NULL CHECK (octet_length(encrypted_request) BETWEEN 30 AND 2097181),
    encrypted_result BYTEA CHECK (encrypted_result IS NULL OR octet_length(encrypted_result) BETWEEN 30 AND 2097181),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at>=created_at+INTERVAL '1 minute' AND expires_at<=created_at+INTERVAL '7 days'),
    updated_at TIMESTAMPTZ NOT NULL CHECK (updated_at>=created_at),
    delivered_session_id UUID,
    delivered_message INTEGER CHECK (delivered_message BETWEEN 1 AND 64),
    delivered_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    UNIQUE(id,device_id,tenant_id,site_id),
    UNIQUE(device_id,request_key),
    FOREIGN KEY(device_id,tenant_id,site_id) REFERENCES mdm_windows_devices(id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(delivered_session_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_syncml_sessions(id,device_id,tenant_id,site_id) ON DELETE RESTRICT,
    CHECK ((delivered_session_id IS NULL AND delivered_message IS NULL AND delivered_at IS NULL) OR (delivered_session_id IS NOT NULL AND delivered_message IS NOT NULL AND delivered_at>=created_at AND delivered_at<expires_at)),
    CHECK ((phase IN ('queued','blocked','canceled','expired') AND delivered_session_id IS NULL) OR (phase IN ('sent','acknowledged','failed','unknown','abandoned') AND delivered_session_id IS NOT NULL)),
    CHECK ((phase IN ('queued','blocked','sent','unknown') AND completed_at IS NULL) OR (phase IN ('acknowledged','failed','abandoned','canceled','expired') AND completed_at>=created_at))
);
CREATE INDEX mdm_windows_csp_command_queue ON mdm_windows_csp_commands(device_id,phase,created_at,id);
CREATE INDEX mdm_windows_csp_command_scope ON mdm_windows_csp_commands(tenant_id,site_id,created_at DESC,id);

ALTER TABLE mdm_windows_syncml_packets ADD CONSTRAINT mdm_windows_syncml_packet_scope_message
    UNIQUE(session_id,device_id,tenant_id,site_id,message_id);

CREATE TABLE mdm_windows_csp_observations (
    command_id UUID NOT NULL,
    device_id UUID NOT NULL,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    session_id UUID NOT NULL,
    message_id INTEGER NOT NULL CHECK (message_id BETWEEN 1 AND 64),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
    encrypted_observation BYTEA NOT NULL CHECK (octet_length(encrypted_observation) BETWEEN 30 AND 2097181),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(command_id,session_id,message_id),
    FOREIGN KEY(command_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_csp_commands(id,device_id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(session_id,device_id,tenant_id,site_id,message_id) REFERENCES mdm_windows_syncml_packets(session_id,device_id,tenant_id,site_id,message_id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE mdm_windows_csp_audit (
    id BIGSERIAL PRIMARY KEY,
    command_id UUID NOT NULL,
    device_id UUID NOT NULL,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    actor TEXT NOT NULL CHECK (octet_length(actor) BETWEEN 1 AND 255),
    action TEXT NOT NULL CHECK (action IN ('command.queued','command.replayed','command.read','command.canceled','command.expired','command.blocked','command.sent','command.observed','command.acknowledged','command.failed','command.unknown','command.abandoned','command.authority_lost')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(command_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_csp_commands(id,device_id,tenant_id,site_id) ON DELETE RESTRICT
);
CREATE INDEX mdm_windows_csp_audit_scope ON mdm_windows_csp_audit(tenant_id,site_id,created_at DESC,id);

CREATE FUNCTION mdm_windows_keep_csp_command() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.device_id,NEW.tenant_id,NEW.site_id,NEW.request_key,NEW.request_digest,NEW.created_by,NEW.created_by_revision,NEW.user_target,NEW.encrypted_request,NEW.created_at,NEW.expires_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.device_id,OLD.tenant_id,OLD.site_id,OLD.request_key,OLD.request_digest,OLD.created_by,OLD.created_by_revision,OLD.user_target,OLD.encrypted_request,OLD.created_at,OLD.expires_at)
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
CREATE TRIGGER mdm_windows_csp_command_identity BEFORE UPDATE OR DELETE ON mdm_windows_csp_commands
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_csp_command();
CREATE TRIGGER mdm_windows_csp_observation_history BEFORE UPDATE OR DELETE ON mdm_windows_csp_observations
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();
CREATE TRIGGER mdm_windows_csp_audit_history BEFORE UPDATE OR DELETE ON mdm_windows_csp_audit
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();
