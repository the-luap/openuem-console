CREATE TABLE mdm_windows_certificate_renewals (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    source_certificate_id UUID NOT NULL,
    renewed_certificate_id UUID NOT NULL UNIQUE,
    request_id BIGINT NOT NULL UNIQUE CHECK (request_id>0),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
    configuration_digest BYTEA NOT NULL CHECK (octet_length(configuration_digest)=32),
    revision BIGINT NOT NULL CHECK (revision>0),
    phase TEXT NOT NULL CHECK (phase IN ('pending','confirmed','canceled')),
    encrypted_record BYTEA NOT NULL CHECK (octet_length(encrypted_record) BETWEEN 30 AND 131101),
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ CHECK (completed_at>=created_at),
    confirmed_session_id UUID,
    confirmed_message_id INTEGER CHECK (confirmed_message_id BETWEEN 1 AND 64),
    confirmed_request_digest BYTEA CHECK (octet_length(confirmed_request_digest)=32),
    UNIQUE(id,device_id,tenant_id,site_id),
    UNIQUE(source_certificate_id,request_digest),
    CHECK (source_certificate_id<>renewed_certificate_id),
    CHECK ((phase='pending')=(completed_at IS NULL)),
    CHECK ((phase='confirmed' AND confirmed_session_id IS NOT NULL AND confirmed_message_id IS NOT NULL AND confirmed_request_digest IS NOT NULL)
        OR (phase<>'confirmed' AND confirmed_session_id IS NULL AND confirmed_message_id IS NULL AND confirmed_request_digest IS NULL)),
    FOREIGN KEY(device_id,tenant_id,site_id) REFERENCES mdm_windows_devices(id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(source_certificate_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_device_certificates(id,device_id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(renewed_certificate_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_device_certificates(id,device_id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(confirmed_session_id,device_id,tenant_id,site_id,confirmed_message_id)
        REFERENCES mdm_windows_syncml_packets(session_id,device_id,tenant_id,site_id,message_id) DEFERRABLE INITIALLY DEFERRED
);
CREATE UNIQUE INDEX mdm_windows_renewal_source ON mdm_windows_certificate_renewals(source_certificate_id) WHERE phase IN ('pending','confirmed');
CREATE UNIQUE INDEX mdm_windows_renewal_candidate ON mdm_windows_certificate_renewals(device_id) WHERE phase='pending';
CREATE INDEX mdm_windows_renewal_history ON mdm_windows_certificate_renewals(device_id,created_at DESC,id);

CREATE TABLE mdm_windows_renewal_audit (
    id BIGSERIAL PRIMARY KEY,
    renewal_id UUID NOT NULL,
    device_id UUID NOT NULL,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    actor TEXT NOT NULL CHECK (octet_length(actor) BETWEEN 1 AND 255),
    action TEXT NOT NULL CHECK (action IN ('renewal.issued','renewal.replayed','renewal.confirmed','renewal.canceled','renewal.read')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(renewal_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_certificate_renewals(id,device_id,tenant_id,site_id) ON DELETE RESTRICT
);
CREATE INDEX mdm_windows_renewal_audit_scope ON mdm_windows_renewal_audit(tenant_id,site_id,id DESC);

CREATE FUNCTION mdm_windows_keep_certificate_renewal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.device_id,NEW.tenant_id,NEW.site_id,NEW.source_certificate_id,NEW.renewed_certificate_id,NEW.request_id,NEW.request_digest,NEW.configuration_digest,NEW.created_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.device_id,OLD.tenant_id,OLD.site_id,OLD.source_certificate_id,OLD.renewed_certificate_id,OLD.request_id,OLD.request_digest,OLD.configuration_digest,OLD.created_at)
        OR OLD.phase<>'pending' OR NEW.phase NOT IN ('confirmed','canceled') OR NEW.revision<>OLD.revision+1
    THEN RAISE EXCEPTION 'native Windows certificate renewal identity and progression are protected'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_windows_certificate_renewal_identity BEFORE UPDATE OR DELETE ON mdm_windows_certificate_renewals
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_certificate_renewal();
CREATE TRIGGER mdm_windows_renewal_audit_history BEFORE UPDATE OR DELETE ON mdm_windows_renewal_audit
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();
