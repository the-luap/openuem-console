CREATE TABLE mdm_windows_update_schedules (
    id UUID PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    request_key UUID NOT NULL,
    ring_id UUID NOT NULL,
    ring_revision BIGINT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(uid) ON DELETE RESTRICT CHECK (octet_length(created_by) BETWEEN 1 AND 255),
    created_by_revision BIGINT NOT NULL CHECK (created_by_revision>0),
    mode TEXT NOT NULL CHECK (mode IN ('apply','remove')),
    lifetime_seconds BIGINT NOT NULL CHECK (lifetime_seconds BETWEEN 60 AND 604800),
    created_at TIMESTAMPTZ NOT NULL,
    not_before TIMESTAMPTZ NOT NULL CHECK (not_before>=created_at-INTERVAL '1 minute' AND not_before<=created_at+INTERVAL '90 days'),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at>created_at AND expires_at>=not_before+INTERVAL '1 minute' AND expires_at<=not_before+INTERVAL '7 days'),
    encrypted_targets BYTEA NOT NULL CHECK (octet_length(encrypted_targets) BETWEEN 30 AND 8221),
    phase TEXT NOT NULL CHECK (phase IN ('scheduled','waiting','activated','blocked','canceled','expired')),
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 1000000),
    updated_at TIMESTAMPTZ NOT NULL CHECK (updated_at>=created_at),
    next_attempt_at TIMESTAMPTZ NOT NULL CHECK (next_attempt_at>=not_before),
    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 0 AND 20000),
    completed_at TIMESTAMPTZ CHECK (completed_at>=created_at AND completed_at=updated_at),
    rollout_id UUID,
    encrypted_state BYTEA NOT NULL CHECK (octet_length(encrypted_state) BETWEEN 30 AND 1053),
    CHECK ((phase IN ('scheduled','waiting'))=(completed_at IS NULL)),
    CHECK ((phase='activated')=(rollout_id IS NOT NULL)),
    CHECK (phase<>'activated' OR (completed_at>=not_before AND completed_at<expires_at)),
    UNIQUE(tenant_id,site_id,request_key),
    UNIQUE(id,tenant_id,site_id),
    UNIQUE(id,ring_id,ring_revision,tenant_id,site_id,created_by,created_by_revision,mode),
    FOREIGN KEY(ring_id,ring_revision,tenant_id,site_id) REFERENCES mdm_windows_update_ring_revisions(ring_id,revision,tenant_id,site_id) ON DELETE RESTRICT
);
CREATE INDEX mdm_windows_update_schedule_due ON mdm_windows_update_schedules(LEAST(next_attempt_at,expires_at),id) WHERE phase IN ('scheduled','waiting');
CREATE INDEX mdm_windows_update_schedule_scope ON mdm_windows_update_schedules(tenant_id,site_id,created_at DESC,id);
CREATE FUNCTION mdm_windows_keep_update_schedule() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.tenant_id,NEW.site_id,NEW.request_key,NEW.ring_id,NEW.ring_revision,NEW.created_by,NEW.created_by_revision,NEW.mode,NEW.lifetime_seconds,NEW.created_at,NEW.not_before,NEW.expires_at,NEW.encrypted_targets)
        IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.site_id,OLD.request_key,OLD.ring_id,OLD.ring_revision,OLD.created_by,OLD.created_by_revision,OLD.mode,OLD.lifetime_seconds,OLD.created_at,OLD.not_before,OLD.expires_at,OLD.encrypted_targets)
        OR OLD.phase NOT IN ('scheduled','waiting') OR NEW.phase NOT IN ('waiting','activated','blocked','canceled','expired')
        OR NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at OR NEW.next_attempt_at<OLD.next_attempt_at
        OR NEW.attempts<OLD.attempts OR NEW.attempts>OLD.attempts+1
    THEN RAISE EXCEPTION 'native Windows update schedule identity and progression are protected'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_windows_update_schedule_identity BEFORE UPDATE OR DELETE ON mdm_windows_update_schedules
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_update_schedule();
ALTER TABLE mdm_windows_update_rollouts ADD COLUMN schedule_id UUID;
ALTER TABLE mdm_windows_update_rollouts ADD CONSTRAINT mdm_windows_update_rollout_schedule
    FOREIGN KEY(schedule_id,ring_id,ring_revision,tenant_id,site_id,created_by,created_by_revision,mode)
    REFERENCES mdm_windows_update_schedules(id,ring_id,ring_revision,tenant_id,site_id,created_by,created_by_revision,mode) ON DELETE RESTRICT;
ALTER TABLE mdm_windows_update_rollouts ADD CONSTRAINT mdm_windows_update_rollout_schedule_identity UNIQUE(id,schedule_id);
CREATE UNIQUE INDEX mdm_windows_update_schedule_activation ON mdm_windows_update_rollouts(schedule_id) WHERE schedule_id IS NOT NULL;
ALTER TABLE mdm_windows_update_schedules ADD CONSTRAINT mdm_windows_update_schedule_rollout
    FOREIGN KEY(rollout_id,id) REFERENCES mdm_windows_update_rollouts(id,schedule_id) ON DELETE RESTRICT;
CREATE TABLE mdm_windows_update_schedule_audit (
    id BIGSERIAL PRIMARY KEY,
    schedule_id UUID NOT NULL,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    actor TEXT NOT NULL CHECK (octet_length(actor) BETWEEN 1 AND 255),
    revision BIGINT NOT NULL CHECK (revision>0),
    action TEXT NOT NULL CHECK (action IN ('schedule.created','schedule.replayed','schedule.read','schedule.waiting','schedule.activated','schedule.blocked','schedule.canceled','schedule.expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(schedule_id,tenant_id,site_id) REFERENCES mdm_windows_update_schedules(id,tenant_id,site_id) ON DELETE RESTRICT
);
CREATE TRIGGER mdm_windows_update_schedule_audit_history BEFORE UPDATE OR DELETE ON mdm_windows_update_schedule_audit
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();
