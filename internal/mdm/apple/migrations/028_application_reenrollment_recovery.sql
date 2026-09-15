-- Stopping evidence is an explicit operator assertion. The historical command
-- outcome remains unknown; reenrollment alone never makes it safe to replay.
CREATE INDEX mdm_apple_device_identity_folded ON mdm_apple_devices(tenant_id,upper(udid)) WHERE udid<>'';
CREATE INDEX mdm_apple_app_prior_pending ON mdm_apple_app_attempts(tenant_id,device_id,package_id)
 WHERE status IN ('queued','sent','not_now','verifying','uncertain');
CREATE TABLE mdm_apple_app_recoveries (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 previous_device_id UUID NOT NULL,
 attempt_id UUID NOT NULL UNIQUE,
 evidence TEXT NOT NULL CHECK(evidence IN ('installer_stopped','device_erased')),
 reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 1000),
 actor TEXT NOT NULL CHECK(length(actor)>0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK(device_id<>previous_device_id),
 FOREIGN KEY(tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id),
 FOREIGN KEY(tenant_id,previous_device_id,attempt_id) REFERENCES mdm_apple_app_attempts(tenant_id,device_id,id)
);
CREATE INDEX mdm_apple_app_recovery_history ON mdm_apple_app_recoveries(tenant_id,device_id,created_at DESC,id DESC);
CREATE FUNCTION mdm_apple_app_recovery_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Application stopping evidence is immutable'; END IF;
 IF NOT EXISTS(SELECT 1 FROM mdm_apple_devices d
   JOIN mdm_apple_devices prior_device ON prior_device.tenant_id=d.tenant_id AND prior_device.udid<>'' AND upper(prior_device.udid)=upper(d.udid)
   JOIN mdm_apple_app_attempts a ON a.tenant_id=prior_device.tenant_id AND a.device_id=prior_device.id
   WHERE d.tenant_id=NEW.tenant_id AND d.id=NEW.device_id AND d.status='enrolled'
   AND prior_device.id=NEW.previous_device_id AND prior_device.status IN ('unenrolled','revoked')
   AND a.id=NEW.attempt_id AND a.status='uncertain' AND a.dispatched_at IS NOT NULL) THEN
  RAISE EXCEPTION 'Stopping evidence must refer to an unresolved retired enrollment on this device';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_app_recovery_guard BEFORE INSERT OR UPDATE OR DELETE ON mdm_apple_app_recoveries
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_app_recovery_guard();
