-- Profile publication and device activation are separate, durable operations.
-- Definition contains the private callback selector and is encrypted at rest.
CREATE TABLE mdm_apple_ade_profiles (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 server_id UUID NOT NULL,
 site_id BIGINT NOT NULL REFERENCES sites(id),
 platform TEXT NOT NULL CHECK(platform IN ('ios','ipados','macos')),
 name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 125),
 definition BYTEA NOT NULL,
 selector_hash TEXT NOT NULL UNIQUE CHECK(selector_hash ~ '^[a-f0-9]{64}$'),
 public_url TEXT NOT NULL,
 removable BOOLEAN NOT NULL,
 await_configuration BOOLEAN NOT NULL,
 device_lock_allowed BOOLEAN NOT NULL DEFAULT false,
 status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','publishing','published','unknown','disabled')),
 remote_id TEXT CHECK(remote_id ~ '^[A-Za-z0-9-]{1,128}$'),
 attempt_id UUID,
 attempted_at TIMESTAMPTZ,
 next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 error TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,server_id,id),
 UNIQUE(server_id,remote_id),
 FOREIGN KEY(tenant_id,server_id) REFERENCES mdm_apple_ade_servers(tenant_id,id),
 CHECK(NOT device_lock_allowed OR platform='macos'),
 CHECK(status<>'published' OR remote_id IS NOT NULL),
 CHECK(status<>'publishing' OR (attempt_id IS NOT NULL AND attempted_at IS NOT NULL))
);
CREATE INDEX mdm_apple_ade_profile_due ON mdm_apple_ade_profiles(next_attempt_at,id) WHERE status IN ('queued','publishing');

CREATE FUNCTION mdm_apple_ade_profile_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.tenant_id,NEW.server_id,NEW.site_id,NEW.platform,NEW.name,NEW.definition,NEW.selector_hash,NEW.public_url,NEW.removable,NEW.await_configuration,NEW.device_lock_allowed)
    IS DISTINCT FROM ROW(OLD.tenant_id,OLD.server_id,OLD.site_id,OLD.platform,OLD.name,OLD.definition,OLD.selector_hash,OLD.public_url,OLD.removable,OLD.await_configuration,OLD.device_lock_allowed)
    OR (OLD.remote_id IS NOT NULL AND NEW.remote_id IS DISTINCT FROM OLD.remote_id) THEN
  RAISE EXCEPTION 'ADE enrollment profile versions are immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_ade_profile_immutable BEFORE UPDATE ON mdm_apple_ade_profiles
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_ade_profile_immutable();

CREATE TABLE mdm_apple_ade_targets (
 tenant_id BIGINT NOT NULL,
 server_id UUID NOT NULL,
 serial TEXT NOT NULL CHECK(serial ~ '^[A-Z0-9]{1,64}$'),
 profile_id UUID,
 revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0),
 generation BIGINT NOT NULL DEFAULT 1 CHECK(generation>0),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','observed','failed','throttled','unavailable')),
 response_status TEXT NOT NULL DEFAULT '',
 remote_profile_id TEXT NOT NULL DEFAULT '',
 remote_status TEXT NOT NULL DEFAULT '',
 observed_at TIMESTAMPTZ,
 attempted_at TIMESTAMPTZ,
 retry_after TIMESTAMPTZ,
 next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,server_id,serial),
 FOREIGN KEY(tenant_id,server_id) REFERENCES mdm_apple_ade_servers(tenant_id,id),
 FOREIGN KEY(tenant_id,server_id,profile_id) REFERENCES mdm_apple_ade_profiles(tenant_id,server_id,id)
);
CREATE INDEX mdm_apple_ade_target_due ON mdm_apple_ade_targets(next_attempt_at) WHERE status<>'failed';

ALTER TABLE mdm_apple_devices DROP CONSTRAINT mdm_apple_devices_enrollment_method_check;
ALTER TABLE mdm_apple_devices ADD CONSTRAINT mdm_apple_devices_enrollment_method_check
 CHECK(enrollment_method IN ('manual_device','automated_device'));
ALTER TABLE mdm_apple_devices ADD COLUMN removal_disallowed BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE mdm_apple_enrollment_layouts ADD COLUMN removal_disallowed BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE mdm_apple_ade_admissions (
 device_id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 server_id UUID NOT NULL,
 serial TEXT NOT NULL,
 generation BIGINT NOT NULL CHECK(generation>0),
 profile_id UUID NOT NULL,
 expected_udid TEXT NOT NULL CHECK(length(expected_udid) BETWEEN 1 AND 64),
 signer_fingerprint TEXT NOT NULL CHECK(signer_fingerprint ~ '^[a-f0-9]{64}$'),
 signed_at TIMESTAMPTZ,
 expires_at TIMESTAMPTZ NOT NULL,
 retry_profile BYTEA,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 awaiting_configuration BOOLEAN,
 awaiting_reported_at TIMESTAMPTZ,
 setup_verify_after TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 next_setup_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 setup_state TEXT NOT NULL DEFAULT 'pending' CHECK(setup_state IN ('pending','awaiting','releasing','complete','failed','not_requested','cancelled')),
 setup_command_id UUID REFERENCES mdm_apple_commands(id),
 setup_error TEXT NOT NULL DEFAULT '',
 setup_updated_at TIMESTAMPTZ,
 UNIQUE(tenant_id,server_id,serial,generation),
 FOREIGN KEY(tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id),
 FOREIGN KEY(tenant_id,server_id,serial) REFERENCES mdm_apple_ade_targets(tenant_id,server_id,serial),
 FOREIGN KEY(tenant_id,server_id,profile_id) REFERENCES mdm_apple_ade_profiles(tenant_id,server_id,id)
);
ALTER TABLE mdm_apple_commands ADD COLUMN ade_setup BOOLEAN NOT NULL DEFAULT false;

CREATE FUNCTION mdm_apple_enrollment_removal_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE expected BOOLEAN;
BEGIN
 IF TG_TABLE_NAME='mdm_apple_devices' THEN
  IF TG_OP='UPDATE' AND ROW(NEW.removal_disallowed,NEW.enrollment_method)
      IS DISTINCT FROM ROW(OLD.removal_disallowed,OLD.enrollment_method) THEN
   RAISE EXCEPTION 'Enrollment method and removal rights are immutable';
  END IF;
  IF NEW.removal_disallowed AND NEW.enrollment_method<>'automated_device' THEN
   RAISE EXCEPTION 'Nonremovable enrollment requires ADE';
  END IF;
 ELSE
  SELECT removal_disallowed INTO expected FROM mdm_apple_devices
   WHERE id=NEW.device_id AND tenant_id=NEW.tenant_id;
  IF expected IS NULL OR NEW.removal_disallowed IS DISTINCT FROM expected THEN
   RAISE EXCEPTION 'Enrollment removal rights do not match the device';
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_device_removal_guard BEFORE INSERT OR UPDATE ON mdm_apple_devices
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_enrollment_removal_guard();
CREATE TRIGGER mdm_apple_layout_removal_guard BEFORE INSERT OR UPDATE ON mdm_apple_enrollment_layouts
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_enrollment_removal_guard();
