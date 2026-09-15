-- The admission keeps its original reviewed pair. Subsequent corrections select
-- immutable pair revisions; profile repairs identify the exact reviewed pair.
ALTER TABLE mdm_apple_ade_device_sso ADD CONSTRAINT mdm_apple_ade_sso_requirement_context
 UNIQUE(tenant_id,device_id,id,profile_id,package_id);
CREATE TABLE mdm_apple_ade_sso_revisions (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 requirement_id UUID NOT NULL,
 profile_id UUID NOT NULL,
 package_id UUID NOT NULL,
 profile_revision_id UUID NOT NULL,
 application_version_id UUID NOT NULL,
 previous_id UUID,
 actor TEXT NOT NULL CHECK(length(actor)>0),
 reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 1000),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,device_id,requirement_id,id),
 UNIQUE(tenant_id,device_id,requirement_id,id,profile_revision_id),
 CHECK((previous_id IS NULL AND id=requirement_id) OR (previous_id IS NOT NULL AND id<>requirement_id AND id<>previous_id)),
 FOREIGN KEY(tenant_id,device_id,requirement_id,profile_id,package_id)
  REFERENCES mdm_apple_ade_device_sso(tenant_id,device_id,id,profile_id,package_id),
 FOREIGN KEY(tenant_id,device_id,requirement_id,previous_id)
  REFERENCES mdm_apple_ade_sso_revisions(tenant_id,device_id,requirement_id,id),
 FOREIGN KEY(tenant_id,profile_id,profile_revision_id) REFERENCES mdm_apple_profile_revisions(tenant_id,profile_id,id),
 FOREIGN KEY(tenant_id,package_id,application_version_id) REFERENCES uem_software_versions(tenant_id,package_id,id)
);
CREATE INDEX mdm_apple_ade_sso_revision_history ON mdm_apple_ade_sso_revisions(tenant_id,device_id,created_at DESC,id DESC);
INSERT INTO mdm_apple_ade_sso_revisions(id,tenant_id,device_id,requirement_id,profile_id,package_id,profile_revision_id,application_version_id,actor,reason,created_at)
 SELECT r.id,r.tenant_id,r.device_id,r.id,r.profile_id,r.package_id,r.profile_revision_id,r.application_version_id,p.approved_by,p.approval_reason,r.created_at
 FROM mdm_apple_ade_device_sso r JOIN mdm_apple_ade_profile_sso p ON p.tenant_id=r.tenant_id AND p.ade_profile_id=r.ade_profile_id;
ALTER TABLE mdm_apple_ade_device_sso ADD COLUMN current_revision_id UUID;
UPDATE mdm_apple_ade_device_sso SET current_revision_id=id;
ALTER TABLE mdm_apple_ade_device_sso ALTER COLUMN current_revision_id SET NOT NULL;
-- Deferral permits the admission and its initial pair to be inserted together.
ALTER TABLE mdm_apple_ade_device_sso ADD CONSTRAINT mdm_apple_ade_sso_current_revision
 FOREIGN KEY(tenant_id,device_id,id,current_revision_id)
 REFERENCES mdm_apple_ade_sso_revisions(tenant_id,device_id,requirement_id,id) DEFERRABLE INITIALLY DEFERRED;

CREATE OR REPLACE FUNCTION mdm_apple_ade_sso_requirement_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'ADE provider requirements are retained'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.current_revision_id<>NEW.id THEN RAISE EXCEPTION 'An ADE provider starts with its original pair'; END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.id,NEW.tenant_id,NEW.device_id,NEW.ade_profile_id,NEW.profile_id,NEW.profile_revision_id,NEW.package_id,NEW.application_version_id,NEW.created_at)
   IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.device_id,OLD.ade_profile_id,OLD.profile_id,OLD.profile_revision_id,OLD.package_id,OLD.application_version_id,OLD.created_at) THEN
  RAISE EXCEPTION 'Original ADE provider requirements are immutable';
 END IF;
 IF NEW.current_revision_id IS DISTINCT FROM OLD.current_revision_id AND NOT EXISTS(
   SELECT 1 FROM mdm_apple_ade_sso_revisions c WHERE c.id=NEW.current_revision_id AND c.requirement_id=NEW.id AND c.previous_id=OLD.current_revision_id) THEN
  RAISE EXCEPTION 'ADE provider correction requires a matching retained pair';
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER mdm_apple_ade_sso_requirement_guard ON mdm_apple_ade_device_sso;
CREATE TRIGGER mdm_apple_ade_sso_requirement_guard BEFORE INSERT OR UPDATE OR DELETE ON mdm_apple_ade_device_sso
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_ade_sso_requirement_guard();
CREATE FUNCTION mdm_apple_ade_sso_revision_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'ADE provider revision history is immutable'; END IF;
 IF NEW.previous_id IS NULL THEN
  IF NOT EXISTS(SELECT 1 FROM mdm_apple_ade_device_sso r WHERE r.id=NEW.requirement_id AND r.current_revision_id=NEW.id
    AND r.profile_revision_id=NEW.profile_revision_id AND r.application_version_id=NEW.application_version_id) THEN
   RAISE EXCEPTION 'Initial ADE provider revision must retain the enrollment pair';
  END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM mdm_apple_ade_device_sso r JOIN mdm_apple_ade_sso_revisions p ON p.id=r.current_revision_id
   JOIN mdm_apple_ade_admissions a ON a.device_id=r.device_id AND a.tenant_id=r.tenant_id
   JOIN mdm_apple_devices d ON d.id=r.device_id AND d.tenant_id=r.tenant_id
   WHERE r.id=NEW.requirement_id AND r.current_revision_id=NEW.previous_id
   AND ROW(p.profile_revision_id,p.application_version_id) IS DISTINCT FROM ROW(NEW.profile_revision_id,NEW.application_version_id)
   AND d.status='enrolled' AND a.awaiting_configuration AND a.setup_state IN ('awaiting','releasing')
   AND NOT EXISTS(SELECT 1 FROM mdm_apple_commands c WHERE c.device_id=r.device_id AND c.tenant_id=r.tenant_id AND c.ade_setup AND c.attempts>0)) THEN
   RAISE EXCEPTION 'ADE provider correction requires the current pair and an unreleased setup hold';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM uem_software_versions v JOIN mdm_apple_profile_revisions p ON p.id=NEW.profile_revision_id AND p.tenant_id=v.tenant_id
   WHERE v.id=NEW.application_version_id AND v.tenant_id=NEW.tenant_id AND v.withdrawn_at IS NULL AND v.kind='macos-pkg' AND p.payload_scope='System') THEN
   RAISE EXCEPTION 'ADE provider correction requires an approved app and System profile';
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_ade_sso_revision_guard BEFORE INSERT OR UPDATE OR DELETE ON mdm_apple_ade_sso_revisions
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_ade_sso_revision_guard();

ALTER TABLE mdm_apple_ade_sso_repairs ADD COLUMN binding_revision_id UUID;
-- Only the new association is backfilled, under the migration's table lock.
-- Every original receipt field remains unchanged and its immutable guard returns
-- before this transaction becomes visible to other connections.
ALTER TABLE mdm_apple_ade_sso_repairs DISABLE TRIGGER mdm_apple_ade_sso_repair_immutable;
UPDATE mdm_apple_ade_sso_repairs SET binding_revision_id=requirement_id;
ALTER TABLE mdm_apple_ade_sso_repairs ENABLE TRIGGER mdm_apple_ade_sso_repair_immutable;
ALTER TABLE mdm_apple_ade_sso_repairs ALTER COLUMN binding_revision_id SET NOT NULL;
DO $$ DECLARE entry RECORD; BEGIN
 FOR entry IN SELECT conname FROM pg_constraint WHERE conrelid='mdm_apple_ade_sso_repairs'::regclass AND confrelid='mdm_apple_ade_device_sso'::regclass AND contype='f' LOOP
  EXECUTE format('ALTER TABLE mdm_apple_ade_sso_repairs DROP CONSTRAINT %I',entry.conname);
 END LOOP;
END $$;
ALTER TABLE mdm_apple_ade_sso_repairs ADD CONSTRAINT mdm_apple_ade_sso_repair_pair
 FOREIGN KEY(tenant_id,device_id,requirement_id,binding_revision_id,profile_revision_id)
 REFERENCES mdm_apple_ade_sso_revisions(tenant_id,device_id,requirement_id,id,profile_revision_id);
