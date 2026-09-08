-- This is an invitation choice, not evidence that Recovery Lock is enabled.
-- Existing invitations and enrollments retain their original access rights.
ALTER TABLE mdm_apple_devices ADD COLUMN device_lock_allowed BOOLEAN NOT NULL DEFAULT false;

CREATE FUNCTION mdm_apple_immutable_device_lock() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.device_lock_allowed IS DISTINCT FROM OLD.device_lock_allowed THEN
  RAISE EXCEPTION 'Enrollment device lock rights cannot change';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_immutable_device_lock BEFORE UPDATE OF device_lock_allowed
 ON mdm_apple_devices FOR EACH ROW EXECUTE FUNCTION mdm_apple_immutable_device_lock();

CREATE FUNCTION mdm_apple_enrollment_rights_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
 allowed BOOLEAN;
 platform TEXT;
 expected_rights BIGINT := 7955;
BEGIN
 SELECT device_lock_allowed,enrollment_platform INTO allowed,platform
 FROM mdm_apple_devices WHERE id=NEW.device_id AND tenant_id=NEW.tenant_id;
 IF allowed THEN
  expected_rights := 7959;
 END IF;
 IF allowed IS NULL OR NEW.access_rights <> expected_rights
    OR (allowed AND platform <> 'macos') THEN
  RAISE EXCEPTION 'Enrollment access rights do not match the invitation';
 END IF;
 IF TG_OP='UPDATE' AND NEW.access_rights IS DISTINCT FROM OLD.access_rights THEN
  RAISE EXCEPTION 'Enrollment access rights cannot change during renewal';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_enrollment_rights_guard BEFORE INSERT OR UPDATE
 ON mdm_apple_enrollment_layouts FOR EACH ROW EXECUTE FUNCTION mdm_apple_enrollment_rights_guard();
