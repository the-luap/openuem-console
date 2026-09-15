-- Console expectations and return keys are separate from the worker registry.
-- History survives enrollment changes and retains encrypted recovery evidence.
CREATE TABLE mdm_apple_filevault_rotations (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 key_id UUID NOT NULL,
 agent_id UUID NOT NULL,
 entity_id UUID NOT NULL,
 nonce_hash TEXT NOT NULL CHECK(nonce_hash ~ '^[a-f0-9]{64}$'),
 context BYTEA NOT NULL,
 reply_private BYTEA NOT NULL,
 actor TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','rotated','unverified','uncertain','invalid','unavailable','unsupported','expired','cancelled','superseded','rejected','resolved')),
 candidate_key_id UUID,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL,
 completed_at TIMESTAMPTZ,
 next_check_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES mdm_apple_devices(tenant_id,site_id,id),
 FOREIGN KEY(tenant_id,device_id,key_id) REFERENCES mdm_apple_filevault_keys(tenant_id,device_id,id),
 FOREIGN KEY(tenant_id,device_id,candidate_key_id) REFERENCES mdm_apple_filevault_keys(tenant_id,device_id,id)
);
CREATE UNIQUE INDEX mdm_apple_filevault_rotation_pending ON mdm_apple_filevault_rotations(device_id) WHERE status IN ('queued','uncertain');
CREATE INDEX mdm_apple_filevault_rotation_history ON mdm_apple_filevault_rotations(device_id,created_at DESC,id DESC);
CREATE INDEX mdm_apple_filevault_rotation_check ON mdm_apple_filevault_rotations(next_check_at,id) WHERE status IN ('queued','uncertain');
ALTER TABLE mdm_apple_filevault_validations ADD COLUMN rotation_id UUID REFERENCES mdm_apple_filevault_rotations(id);

-- Old worker/console replicas must also stop delivery when native authority or
-- the escrow policy changes. Native-only installations have no registry table.
CREATE FUNCTION mdm_apple_cancel_filevault_rotation(agent UUID,native UUID,undelivered_only BOOLEAN DEFAULT false) RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
 IF to_regclass('uem_agent_rotation_tasks') IS NOT NULL THEN
  UPDATE uem_agent_rotation_tasks SET status='cancelled',envelope='\x',completed_at=clock_timestamp()
   WHERE status IN ('pending','uncertain') AND (device_id=agent OR native_id=native)
   AND (NOT undelivered_only OR delivered_at IS NULL);
 END IF;
END $$;

CREATE FUNCTION mdm_apple_filevault_rotation_policy_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.desired IS DISTINCT FROM OLD.desired OR NEW.escrow_id IS DISTINCT FROM OLD.escrow_id OR
    (OLD.phase='active' AND NEW.phase<>'active') THEN
  PERFORM mdm_apple_cancel_filevault_rotation(NULL,OLD.device_id);
 ELSIF NEW.current_key_id IS DISTINCT FROM OLD.current_key_id THEN
  PERFORM mdm_apple_cancel_filevault_rotation(NULL,OLD.device_id,true);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER mdm_apple_filevault_rotation_policy_change AFTER UPDATE ON mdm_apple_filevault_policies
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_filevault_rotation_policy_change();

CREATE FUNCTION mdm_apple_filevault_rotation_native_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status IS DISTINCT FROM OLD.status OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
    NEW.site_id IS DISTINCT FROM OLD.site_id OR NEW.model IS DISTINCT FROM OLD.model OR NEW.serial_number IS DISTINCT FROM OLD.serial_number THEN
  PERFORM mdm_apple_cancel_filevault_rotation(NULL,OLD.id);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER mdm_apple_filevault_rotation_native_change AFTER UPDATE ON mdm_apple_devices
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_filevault_rotation_native_change();
