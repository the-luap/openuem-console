-- Enrollment policies pin approved app revisions. Later per-device corrections
-- retain the original requirement and their own immutable change history.
CREATE TABLE mdm_apple_ade_profile_apps (
 tenant_id BIGINT NOT NULL,
 server_id UUID NOT NULL,
 profile_id UUID NOT NULL,
 package_id UUID NOT NULL,
 version_id UUID NOT NULL,
 PRIMARY KEY(profile_id,package_id),
 UNIQUE(tenant_id,profile_id,package_id,version_id),
 FOREIGN KEY(tenant_id,server_id,profile_id) REFERENCES mdm_apple_ade_profiles(tenant_id,server_id,id),
 FOREIGN KEY(tenant_id,package_id,version_id) REFERENCES uem_software_versions(tenant_id,package_id,id)
);
CREATE FUNCTION mdm_apple_ade_app_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'ADE application requirements are immutable'; END IF;
 IF NOT EXISTS(SELECT 1 FROM mdm_apple_ade_profiles p JOIN uem_software_versions v ON v.id=NEW.version_id AND v.tenant_id=p.tenant_id
     JOIN uem_software_packages k ON k.id=v.package_id AND k.tenant_id=v.tenant_id
     WHERE p.id=NEW.profile_id AND p.tenant_id=NEW.tenant_id AND p.server_id=NEW.server_id
     AND p.platform='macos' AND p.await_configuration AND p.status='queued' AND p.attempt_id IS NULL
     AND v.withdrawn_at IS NULL AND v.kind='macos-pkg' AND k.platform='macos' AND k.id=NEW.package_id) THEN
  RAISE EXCEPTION 'ADE application requirement must use an approved Mac package';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_ade_app_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON mdm_apple_ade_profile_apps
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_ade_app_policy_guard();

ALTER TABLE mdm_apple_ade_admissions ADD CONSTRAINT mdm_apple_ade_admission_profile_identity UNIQUE(tenant_id,device_id,profile_id);
CREATE TABLE mdm_apple_ade_device_apps (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 profile_id UUID NOT NULL,
 package_id UUID NOT NULL,
 original_version_id UUID NOT NULL,
 version_id UUID NOT NULL,
 error TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(device_id,package_id),
 UNIQUE(tenant_id,device_id,package_id,id),
 FOREIGN KEY(tenant_id,device_id,profile_id) REFERENCES mdm_apple_ade_admissions(tenant_id,device_id,profile_id),
 FOREIGN KEY(tenant_id,profile_id,package_id,original_version_id) REFERENCES mdm_apple_ade_profile_apps(tenant_id,profile_id,package_id,version_id),
 FOREIGN KEY(tenant_id,package_id,version_id) REFERENCES uem_software_versions(tenant_id,package_id,id)
);
CREATE TABLE mdm_apple_ade_app_changes (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 package_id UUID NOT NULL,
 requirement_id UUID NOT NULL,
 previous_version_id UUID NOT NULL,
 version_id UUID NOT NULL,
 actor TEXT NOT NULL CHECK(length(actor)>0),
 reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 1000),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(requirement_id,id),
 FOREIGN KEY(tenant_id,device_id,package_id,requirement_id) REFERENCES mdm_apple_ade_device_apps(tenant_id,device_id,package_id,id),
 FOREIGN KEY(tenant_id,package_id,previous_version_id) REFERENCES uem_software_versions(tenant_id,package_id,id),
 FOREIGN KEY(tenant_id,package_id,version_id) REFERENCES uem_software_versions(tenant_id,package_id,id),
 CHECK(previous_version_id<>version_id)
);
CREATE INDEX mdm_apple_ade_app_change_history ON mdm_apple_ade_app_changes(requirement_id,created_at DESC,id DESC);
ALTER TABLE mdm_apple_ade_device_apps ADD COLUMN current_change_id UUID;
ALTER TABLE mdm_apple_ade_device_apps ADD CONSTRAINT mdm_apple_ade_app_current_change
 FOREIGN KEY(id,current_change_id) REFERENCES mdm_apple_ade_app_changes(requirement_id,id);
CREATE FUNCTION mdm_apple_ade_device_app_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Original ADE application requirements are retained'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.original_version_id<>NEW.version_id OR NEW.current_change_id IS NOT NULL THEN
   RAISE EXCEPTION 'An ADE application starts with its original approved revision';
  END IF;
 ELSE
  IF ROW(NEW.id,NEW.tenant_id,NEW.device_id,NEW.profile_id,NEW.package_id,NEW.original_version_id,NEW.created_at)
    IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.device_id,OLD.profile_id,OLD.package_id,OLD.original_version_id,OLD.created_at) THEN
   RAISE EXCEPTION 'Original ADE application requirements are immutable';
  END IF;
  IF NEW.version_id IS DISTINCT FROM OLD.version_id OR NEW.current_change_id IS DISTINCT FROM OLD.current_change_id THEN
   IF NOT EXISTS(SELECT 1 FROM mdm_apple_ade_app_changes c WHERE c.requirement_id=NEW.id AND c.id=NEW.current_change_id
       AND c.previous_version_id=OLD.version_id AND c.version_id=NEW.version_id) THEN
    RAISE EXCEPTION 'ADE application replacement requires a matching retained change';
   END IF;
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_ade_device_app_guard BEFORE INSERT OR UPDATE OR DELETE ON mdm_apple_ade_device_apps
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_ade_device_app_guard();
CREATE FUNCTION mdm_apple_ade_app_change_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'ADE application change history is immutable'; END;
$$;
CREATE TRIGGER mdm_apple_ade_app_change_immutable BEFORE UPDATE OR DELETE ON mdm_apple_ade_app_changes
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_ade_app_change_immutable();
