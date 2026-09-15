ALTER TABLE mdm_windows_invitations ADD CONSTRAINT mdm_windows_invitation_scope UNIQUE(id,tenant_id,site_id);
ALTER TABLE mdm_windows_audit ADD CONSTRAINT mdm_windows_audit_invitation_scope
    FOREIGN KEY(resource_id,tenant_id,site_id) REFERENCES mdm_windows_invitations(id,tenant_id,site_id) ON DELETE RESTRICT;

CREATE TABLE mdm_windows_devices (
    id UUID PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    invitation_id UUID NOT NULL UNIQUE,
    reported_device_id TEXT NOT NULL CHECK (octet_length(reported_device_id) BETWEEN 1 AND 256),
    device_name TEXT NOT NULL CHECK (octet_length(device_name) BETWEEN 1 AND 256),
    enrollment_type TEXT NOT NULL CHECK (enrollment_type IN ('Full','Device')),
    os_edition BIGINT NOT NULL CHECK (os_edition BETWEEN 0 AND 4294967295),
    os_version TEXT NOT NULL CHECK (octet_length(os_version) BETWEEN 1 AND 64),
    application_version TEXT NOT NULL CHECK (octet_length(application_version) BETWEEN 1 AND 64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    revoked_at TIMESTAMPTZ CHECK (revoked_at>=created_at),
    UNIQUE(id,tenant_id,site_id),
    UNIQUE(id,invitation_id,tenant_id,site_id),
    FOREIGN KEY(invitation_id,tenant_id,site_id) REFERENCES mdm_windows_invitations(id,tenant_id,site_id) ON DELETE RESTRICT
);
CREATE INDEX mdm_windows_devices_scope ON mdm_windows_devices(tenant_id,site_id,created_at DESC,id);

CREATE TABLE mdm_windows_device_certificates (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    authority_id UUID NOT NULL,
    certificate BYTEA NOT NULL CHECK (octet_length(certificate) BETWEEN 1 AND 16384),
    fingerprint BYTEA NOT NULL UNIQUE CHECK (octet_length(fingerprint)=32),
    public_key_fingerprint BYTEA NOT NULL CHECK (octet_length(public_key_fingerprint)=32),
    serial BYTEA NOT NULL CHECK (octet_length(serial) BETWEEN 1 AND 20),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at>issued_at),
    revoked_at TIMESTAMPTZ CHECK (revoked_at>=issued_at),
    UNIQUE(id,device_id,tenant_id,site_id),
    UNIQUE(authority_id,serial),
    FOREIGN KEY(device_id,tenant_id,site_id) REFERENCES mdm_windows_devices(id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(authority_id,tenant_id) REFERENCES mdm_windows_authorities(id,tenant_id) ON DELETE RESTRICT
);

CREATE TABLE mdm_windows_enrollments (
    invitation_id UUID PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    device_id UUID NOT NULL UNIQUE,
    certificate_id UUID NOT NULL UNIQUE,
    request_id BIGSERIAL NOT NULL UNIQUE,
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
    configuration_digest BYTEA NOT NULL CHECK (octet_length(configuration_digest)=32),
    encrypted_provisioning BYTEA NOT NULL CHECK (octet_length(encrypted_provisioning) BETWEEN 30 AND 65565),
    encrypted_auth BYTEA NOT NULL CHECK (octet_length(encrypted_auth) BETWEEN 30 AND 8221),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(invitation_id,tenant_id,site_id) REFERENCES mdm_windows_invitations(id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(device_id,tenant_id,site_id) REFERENCES mdm_windows_devices(id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(device_id,invitation_id,tenant_id,site_id) REFERENCES mdm_windows_devices(id,invitation_id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(certificate_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_device_certificates(id,device_id,tenant_id,site_id) ON DELETE RESTRICT
);

CREATE FUNCTION mdm_windows_keep_device_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.tenant_id,NEW.site_id,NEW.invitation_id,NEW.reported_device_id,NEW.device_name,NEW.enrollment_type,NEW.os_edition,NEW.os_version,NEW.application_version,NEW.created_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.site_id,OLD.invitation_id,OLD.reported_device_id,OLD.device_name,OLD.enrollment_type,OLD.os_edition,OLD.os_version,OLD.application_version,OLD.created_at)
        OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
    THEN RAISE EXCEPTION 'native Windows device identity is immutable'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_windows_device_identity BEFORE UPDATE OR DELETE ON mdm_windows_devices
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_device_identity();

CREATE FUNCTION mdm_windows_keep_device_certificate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.device_id,NEW.tenant_id,NEW.site_id,NEW.authority_id,NEW.certificate,NEW.fingerprint,NEW.public_key_fingerprint,NEW.serial,NEW.issued_at,NEW.expires_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.device_id,OLD.tenant_id,OLD.site_id,OLD.authority_id,OLD.certificate,OLD.fingerprint,OLD.public_key_fingerprint,OLD.serial,OLD.issued_at,OLD.expires_at)
        OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
    THEN RAISE EXCEPTION 'native Windows device certificate is immutable'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_windows_device_certificate BEFORE UPDATE OR DELETE ON mdm_windows_device_certificates
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_device_certificate();

CREATE FUNCTION mdm_windows_keep_enrollment_result() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'native Windows enrollment result is immutable'; END;
$$;
CREATE TRIGGER mdm_windows_enrollment_result BEFORE UPDATE OR DELETE ON mdm_windows_enrollments
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_enrollment_result();

ALTER TABLE mdm_windows_audit DROP CONSTRAINT mdm_windows_audit_action_check;
ALTER TABLE mdm_windows_audit ADD CONSTRAINT mdm_windows_audit_action_check
    CHECK (action IN ('invitation.created','invitation.read','invitation.revoked','invitation.consumed','policy.read','enrollment.issued','enrollment.replayed'));
