CREATE TABLE mdm_windows_certificate_reminders (
    id UUID PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL CHECK (site_id>=0),
    authority_id UUID NOT NULL,
    device_id UUID,
    kind TEXT NOT NULL CHECK (kind IN ('device_expiry','issuer_expiry','issuer_issuance')),
    resource_id UUID NOT NULL,
    certificate_id UUID GENERATED ALWAYS AS (CASE WHEN kind='device_expiry' THEN resource_id END) STORED,
    fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    deadline TIMESTAMPTZ NOT NULL,
    stage INTEGER NOT NULL CHECK (stage IN (0,1,7,14,30)),
    created_at TIMESTAMPTZ NOT NULL,
    encrypted_identity BYTEA NOT NULL CHECK (octet_length(encrypted_identity) BETWEEN 30 AND 8221),
    CHECK ((kind='device_expiry')=(device_id IS NOT NULL)),
    CHECK ((kind='device_expiry')=(site_id>0)),
    CHECK (kind='device_expiry' OR resource_id=authority_id),
    UNIQUE(kind,resource_id,stage),
    FOREIGN KEY(certificate_id,device_id,tenant_id,site_id) REFERENCES mdm_windows_device_certificates(id,device_id,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(authority_id,tenant_id) REFERENCES mdm_windows_authorities(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY(device_id,tenant_id,site_id) REFERENCES mdm_windows_devices(id,tenant_id,site_id) ON DELETE RESTRICT
);
CREATE INDEX mdm_windows_certificate_reminders_scope ON mdm_windows_certificate_reminders(tenant_id,site_id,created_at DESC,id);
CREATE TRIGGER mdm_windows_certificate_reminder_history BEFORE UPDATE OR DELETE ON mdm_windows_certificate_reminders
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();

CREATE TABLE mdm_windows_certificate_deliveries (
    id UUID PRIMARY KEY,
    reminder_id UUID NOT NULL REFERENCES mdm_windows_certificate_reminders(id) ON DELETE RESTRICT,
    user_id TEXT NOT NULL CHECK (octet_length(user_id) BETWEEN 1 AND 255),
    phase TEXT NOT NULL CHECK (phase IN ('pending','accepted','canceled')),
    revision BIGINT NOT NULL CHECK (revision>0),
    attempts BIGINT NOT NULL CHECK (attempts BETWEEN 0 AND 2147483647),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL CHECK(updated_at>=created_at),
    next_attempt_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    reason TEXT NOT NULL CHECK(reason IN ('','smtp_unavailable','smtp_failed','recipient_unavailable','superseded')),
    encrypted_state BYTEA NOT NULL CHECK (octet_length(encrypted_state) BETWEEN 30 AND 8221),
    CHECK ((phase='accepted')=(accepted_at IS NOT NULL)),
    CHECK (accepted_at IS NULL OR accepted_at=updated_at),
    CHECK (phase<>'canceled' OR reason IN ('recipient_unavailable','superseded')),
    CHECK (phase<>'accepted' OR (reason='' AND attempts>0)),
    CHECK (phase<>'pending' OR reason IN ('','smtp_unavailable','smtp_failed')),
    UNIQUE(reminder_id,user_id)
);
CREATE INDEX mdm_windows_certificate_delivery_due ON mdm_windows_certificate_deliveries(next_attempt_at,id) WHERE phase='pending';
CREATE FUNCTION mdm_windows_keep_certificate_delivery() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.reminder_id,NEW.user_id,NEW.created_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.reminder_id,OLD.user_id,OLD.created_at)
        OR NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at
        OR OLD.phase='accepted' OR NEW.attempts<OLD.attempts OR NEW.attempts>OLD.attempts+1
        OR (OLD.phase='canceled' AND (OLD.reason<>'recipient_unavailable' OR NEW.phase<>'pending'))
    THEN RAISE EXCEPTION 'native Windows certificate delivery identity and progression are protected'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER mdm_windows_certificate_delivery_identity BEFORE UPDATE OR DELETE ON mdm_windows_certificate_deliveries
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_certificate_delivery();

CREATE TABLE mdm_windows_certificate_reminder_audit (
    id BIGSERIAL PRIMARY KEY,
    reminder_id UUID NOT NULL REFERENCES mdm_windows_certificate_reminders(id) ON DELETE RESTRICT,
    delivery_id UUID REFERENCES mdm_windows_certificate_deliveries(id) ON DELETE RESTRICT,
    actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
    action TEXT NOT NULL CHECK(action IN ('reminder.created','reminder.read','delivery.created','delivery.retry','delivery.accepted','delivery.canceled','delivery.resumed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((action LIKE 'delivery.%')=(delivery_id IS NOT NULL))
);
CREATE TRIGGER mdm_windows_certificate_reminder_audit_history BEFORE UPDATE OR DELETE ON mdm_windows_certificate_reminder_audit
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();

ALTER TABLE mdm_windows_console_audit DROP CONSTRAINT mdm_windows_console_audit_action_check;
ALTER TABLE mdm_windows_console_audit ADD CONSTRAINT mdm_windows_console_audit_action_check
    CHECK (action IN ('invitations.list','devices.list','device.read','device.revoked','authority.status','certificate_health.read','certificate_reminders.read'));
