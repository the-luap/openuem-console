CREATE TABLE mdm_windows_update_rings (
    id UUID PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    current_revision BIGINT NOT NULL CHECK (current_revision BETWEEN 1 AND 1000000),
    UNIQUE(id,tenant_id,site_id)
);
CREATE TABLE mdm_windows_update_ring_revisions (
    ring_id UUID NOT NULL,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 1000000),
    request_key UUID NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(uid) ON DELETE RESTRICT,
    created_by_revision BIGINT NOT NULL CHECK (created_by_revision>0),
    enabled BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    encrypted_intent BYTEA NOT NULL CHECK (octet_length(encrypted_intent) BETWEEN 30 AND 8221),
    PRIMARY KEY(ring_id,revision),
    UNIQUE(ring_id,revision,tenant_id,site_id),
    UNIQUE(ring_id,request_key),
    FOREIGN KEY(ring_id,tenant_id,site_id) REFERENCES mdm_windows_update_rings(id,tenant_id,site_id) ON DELETE RESTRICT
);
ALTER TABLE mdm_windows_update_rings ADD CONSTRAINT mdm_windows_update_ring_head
    FOREIGN KEY(id,current_revision,tenant_id,site_id)
    REFERENCES mdm_windows_update_ring_revisions(ring_id,revision,tenant_id,site_id) DEFERRABLE INITIALLY DEFERRED;
CREATE FUNCTION mdm_windows_keep_update_ring() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.tenant_id,NEW.site_id) IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.site_id)
        OR NEW.current_revision<>OLD.current_revision+1
    THEN RAISE EXCEPTION 'native Windows update ring identity and revision progression are protected'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_windows_update_ring_identity BEFORE UPDATE OR DELETE ON mdm_windows_update_rings
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_update_ring();
CREATE TRIGGER mdm_windows_update_ring_revision_history BEFORE UPDATE OR DELETE ON mdm_windows_update_ring_revisions
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();
CREATE INDEX mdm_windows_update_ring_revision_scope ON mdm_windows_update_ring_revisions(tenant_id,site_id,created_at DESC,ring_id);

CREATE TABLE mdm_windows_update_rollouts (
    id UUID PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    request_key UUID NOT NULL,
    ring_id UUID NOT NULL,
    ring_revision BIGINT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(uid) ON DELETE RESTRICT,
    created_by_revision BIGINT NOT NULL CHECK (created_by_revision>0),
    mode TEXT NOT NULL CHECK (mode IN ('apply','remove')),
    lifetime_seconds BIGINT NOT NULL CHECK (lifetime_seconds BETWEEN 60 AND 604800),
    created_at TIMESTAMPTZ NOT NULL,
    encrypted_targets BYTEA NOT NULL CHECK (octet_length(encrypted_targets) BETWEEN 30 AND 8221),
    UNIQUE(tenant_id,site_id,request_key),
    UNIQUE(id,ring_id,ring_revision,tenant_id,site_id),
    UNIQUE(id,ring_id,ring_revision,tenant_id,site_id,created_by,created_by_revision,mode),
    FOREIGN KEY(ring_id,ring_revision,tenant_id,site_id) REFERENCES mdm_windows_update_ring_revisions(ring_id,revision,tenant_id,site_id) ON DELETE RESTRICT
);
CREATE TRIGGER mdm_windows_update_rollout_history BEFORE UPDATE OR DELETE ON mdm_windows_update_rollouts
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();
ALTER TABLE mdm_windows_update_runs ADD COLUMN ring_id UUID;
ALTER TABLE mdm_windows_update_runs ADD COLUMN ring_revision BIGINT;
ALTER TABLE mdm_windows_update_runs ADD COLUMN rollout_id UUID;
ALTER TABLE mdm_windows_update_runs ADD CONSTRAINT mdm_windows_update_run_source CHECK (
    (ring_id IS NULL AND ring_revision IS NULL AND rollout_id IS NULL) OR
    (ring_id IS NOT NULL AND ring_revision IS NOT NULL AND ring_revision>0 AND rollout_id IS NOT NULL));
ALTER TABLE mdm_windows_update_runs ADD CONSTRAINT mdm_windows_update_run_rollout
    FOREIGN KEY(rollout_id,ring_id,ring_revision,tenant_id,site_id,created_by,created_by_revision,mode)
    REFERENCES mdm_windows_update_rollouts(id,ring_id,ring_revision,tenant_id,site_id,created_by,created_by_revision,mode) ON DELETE RESTRICT;
CREATE UNIQUE INDEX mdm_windows_update_rollout_device ON mdm_windows_update_runs(rollout_id,device_id) WHERE rollout_id IS NOT NULL;

CREATE TABLE mdm_windows_update_ring_audit (
    id BIGSERIAL PRIMARY KEY,
    ring_id UUID NOT NULL,
    ring_revision BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    actor TEXT NOT NULL CHECK (octet_length(actor) BETWEEN 1 AND 255),
    action TEXT NOT NULL CHECK (action IN ('ring.saved','ring.replayed','ring.read','rollout.created','rollout.replayed','rollout.read')),
    rollout_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((action IN ('ring.saved','ring.replayed','ring.read'))=(rollout_id IS NULL)),
    FOREIGN KEY(ring_id,ring_revision,tenant_id,site_id) REFERENCES mdm_windows_update_ring_revisions(ring_id,revision,tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(rollout_id,ring_id,ring_revision,tenant_id,site_id) REFERENCES mdm_windows_update_rollouts(id,ring_id,ring_revision,tenant_id,site_id) ON DELETE RESTRICT
);
CREATE TRIGGER mdm_windows_update_ring_audit_history BEFORE UPDATE OR DELETE ON mdm_windows_update_ring_audit
    FOR EACH ROW EXECUTE FUNCTION mdm_windows_keep_management_history();
