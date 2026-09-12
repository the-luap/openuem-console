-- Passwords remain separate from inventory, command payloads and lifecycle data.
CREATE TABLE mdm_apple_recovery_lock_keys (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 password BYTEA NOT NULL CHECK(octet_length(password)>28),
 source TEXT NOT NULL CHECK(source IN ('generated','imported')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 verified_at TIMESTAMPTZ,
 rejected_at TIMESTAMPTZ,
 UNIQUE(tenant_id,device_id,id),
 FOREIGN KEY(tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX mdm_apple_recovery_lock_key_history ON mdm_apple_recovery_lock_keys(tenant_id,device_id,created_at DESC,id);

CREATE TABLE mdm_apple_recovery_lock_state (
 device_id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 current_key_id UUID,
 evidence TEXT NOT NULL DEFAULT 'unknown' CHECK(evidence IN ('unknown','verified','removal_acknowledged')),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,device_id,current_key_id) REFERENCES mdm_apple_recovery_lock_keys(tenant_id,device_id,id),
 CHECK(evidence<>'verified' OR current_key_id IS NOT NULL),
 CHECK(evidence<>'removal_acknowledged' OR current_key_id IS NULL)
);

CREATE TABLE mdm_apple_recovery_lock_attempts (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 operation TEXT NOT NULL CHECK(operation IN ('set','rotate','remove','verify','import')),
 status TEXT NOT NULL CHECK(status IN ('checking','queued','sent','verifying','uncertain','verified','removed','resolved','failed','cancelled')),
 previous_key_id UUID,
 candidate_key_id UUID,
 command_id UUID,
 set_command_id UUID,
 error TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 completed_at TIMESTAMPTZ,
 next_check_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,device_id,id),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES mdm_apple_devices(tenant_id,site_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,device_id,previous_key_id) REFERENCES mdm_apple_recovery_lock_keys(tenant_id,device_id,id),
 FOREIGN KEY(tenant_id,device_id,candidate_key_id) REFERENCES mdm_apple_recovery_lock_keys(tenant_id,device_id,id),
 CHECK(operation<>'remove' OR (previous_key_id IS NOT NULL AND candidate_key_id IS NULL)),
 CHECK(operation NOT IN ('rotate','set','import','verify') OR candidate_key_id IS NOT NULL),
 CHECK(operation<>'rotate' OR (previous_key_id IS NOT NULL AND candidate_key_id<>previous_key_id))
);
CREATE UNIQUE INDEX mdm_apple_recovery_lock_active ON mdm_apple_recovery_lock_attempts(device_id) WHERE status IN ('checking','queued','sent','verifying','uncertain');
CREATE INDEX mdm_apple_recovery_lock_due ON mdm_apple_recovery_lock_attempts(next_check_at,id) WHERE status IN ('checking','queued','sent','verifying','uncertain');
CREATE INDEX mdm_apple_recovery_lock_history ON mdm_apple_recovery_lock_attempts(tenant_id,device_id,created_at DESC,id);

ALTER TABLE mdm_apple_commands ADD COLUMN recovery_lock BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE mdm_apple_commands ADD CONSTRAINT mdm_apple_recovery_lock_command_kind CHECK(recovery_lock=(request_type IN ('SetRecoveryLock','VerifyRecoveryLock')));

CREATE TABLE mdm_apple_recovery_lock_commands (
 command_id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 attempt_id UUID NOT NULL,
 purpose TEXT NOT NULL CHECK(purpose IN ('current','set','candidate','previous')),
 dispatched_at TIMESTAMPTZ,
 result TEXT NOT NULL DEFAULT '' CHECK(result IN ('','acknowledged','verified','rejected','error')),
 result_at TIMESTAMPTZ,
 UNIQUE(tenant_id,device_id,attempt_id,command_id),
 FOREIGN KEY(tenant_id,device_id,command_id) REFERENCES mdm_apple_commands(tenant_id,device_id,id),
 FOREIGN KEY(tenant_id,device_id,attempt_id) REFERENCES mdm_apple_recovery_lock_attempts(tenant_id,device_id,id) ON DELETE CASCADE,
 CHECK((result='')=(result_at IS NULL)),
 CHECK(result_at IS NULL OR dispatched_at IS NOT NULL)
);
CREATE UNIQUE INDEX mdm_apple_recovery_lock_single_set ON mdm_apple_recovery_lock_commands(attempt_id) WHERE purpose='set';
ALTER TABLE mdm_apple_recovery_lock_attempts ADD FOREIGN KEY(tenant_id,device_id,id,command_id) REFERENCES mdm_apple_recovery_lock_commands(tenant_id,device_id,attempt_id,command_id);
ALTER TABLE mdm_apple_recovery_lock_attempts ADD FOREIGN KEY(tenant_id,device_id,id,set_command_id) REFERENCES mdm_apple_recovery_lock_commands(tenant_id,device_id,attempt_id,command_id);

-- A generic retry must never turn a delivered password mutation into new work.
CREATE FUNCTION mdm_apple_recovery_lock_delivery_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.request_type='SetRecoveryLock' AND (NEW.attempts>1 OR (NEW.attempts>0 AND octet_length(NEW.payload)>0)) THEN
  RAISE EXCEPTION 'Recovery Lock mutation delivery must consume its payload once';
 END IF;
 IF OLD.recovery_lock AND (NOT NEW.recovery_lock OR NEW.request_type<>OLD.request_type) THEN
  RAISE EXCEPTION 'Recovery Lock command ownership is immutable';
 END IF;
 IF OLD.request_type='SetRecoveryLock' AND OLD.attempts>0
    AND (NEW.attempts<>OLD.attempts OR NEW.status='queued' OR octet_length(NEW.payload)>0) THEN
  RAISE EXCEPTION 'A Recovery Lock mutation cannot be delivered again';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_recovery_lock_delivery_guard BEFORE UPDATE ON mdm_apple_commands FOR EACH ROW EXECUTE FUNCTION mdm_apple_recovery_lock_delivery_guard();
