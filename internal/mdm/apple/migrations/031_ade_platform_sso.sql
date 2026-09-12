-- A provider binding names the exact retained profile and approved host app.
-- The configuration catalog may advance while this enrollment policy remains
-- unchanged. Disabling the ADE policy preserves its original provider review.
CREATE TABLE mdm_apple_ade_profile_sso (
 tenant_id BIGINT NOT NULL,
 server_id UUID NOT NULL,
 ade_profile_id UUID PRIMARY KEY,
 profile_id UUID NOT NULL,
 profile_revision_id UUID NOT NULL,
 package_id UUID NOT NULL,
 application_version_id UUID NOT NULL,
 approval_reason TEXT NOT NULL CHECK(length(approval_reason) BETWEEN 1 AND 1000),
 approved_by TEXT NOT NULL CHECK(length(approved_by)>0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,ade_profile_id,profile_id,profile_revision_id,package_id,application_version_id),
 FOREIGN KEY(tenant_id,server_id,ade_profile_id) REFERENCES mdm_apple_ade_profiles(tenant_id,server_id,id),
 FOREIGN KEY(tenant_id,profile_id,profile_revision_id) REFERENCES mdm_apple_profile_revisions(tenant_id,profile_id,id),
 FOREIGN KEY(tenant_id,ade_profile_id,package_id,application_version_id) REFERENCES mdm_apple_ade_profile_apps(tenant_id,profile_id,package_id,version_id)
);
CREATE FUNCTION mdm_apple_ade_sso_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'ADE provider bindings are immutable'; END IF;
 IF NOT EXISTS(SELECT 1 FROM mdm_apple_ade_profiles p JOIN mdm_apple_profile_revisions r ON r.id=NEW.profile_revision_id AND r.tenant_id=p.tenant_id
   WHERE p.id=NEW.ade_profile_id AND p.tenant_id=NEW.tenant_id AND p.status='queued' AND p.attempt_id IS NULL
   AND p.platform='macos' AND p.await_configuration AND p.admin_options->>'primary_account'='skip'
   AND r.profile_id=NEW.profile_id AND r.payload_scope='System') THEN
  RAISE EXCEPTION 'ADE provider binding requires a held Mac setup with a managed administrator';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_ade_sso_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON mdm_apple_ade_profile_sso
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_ade_sso_policy_guard();

CREATE TABLE mdm_apple_ade_device_sso (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL UNIQUE,
 ade_profile_id UUID NOT NULL,
 profile_id UUID NOT NULL,
 profile_revision_id UUID NOT NULL,
 package_id UUID NOT NULL,
 application_version_id UUID NOT NULL,
 error TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,device_id,id,profile_revision_id),
 FOREIGN KEY(tenant_id,device_id,ade_profile_id) REFERENCES mdm_apple_ade_admissions(tenant_id,device_id,profile_id),
 FOREIGN KEY(tenant_id,ade_profile_id,profile_id,profile_revision_id,package_id,application_version_id)
  REFERENCES mdm_apple_ade_profile_sso(tenant_id,ade_profile_id,profile_id,profile_revision_id,package_id,application_version_id)
);
CREATE FUNCTION mdm_apple_ade_sso_requirement_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'ADE provider requirements are retained'; END IF;
 IF ROW(NEW.id,NEW.tenant_id,NEW.device_id,NEW.ade_profile_id,NEW.profile_id,NEW.profile_revision_id,NEW.package_id,NEW.application_version_id,NEW.created_at)
   IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.device_id,OLD.ade_profile_id,OLD.profile_id,OLD.profile_revision_id,OLD.package_id,OLD.application_version_id,OLD.created_at) THEN
  RAISE EXCEPTION 'ADE provider requirements are immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_ade_sso_requirement_guard BEFORE UPDATE OR DELETE ON mdm_apple_ade_device_sso
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_ade_sso_requirement_guard();

CREATE TABLE mdm_apple_ade_sso_repairs (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 requirement_id UUID NOT NULL,
 profile_revision_id UUID NOT NULL,
 actor TEXT NOT NULL CHECK(length(actor)>0),
 reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 1000),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,device_id,requirement_id,profile_revision_id)
  REFERENCES mdm_apple_ade_device_sso(tenant_id,device_id,id,profile_revision_id)
);
CREATE INDEX mdm_apple_ade_sso_repair_history ON mdm_apple_ade_sso_repairs(tenant_id,device_id,created_at DESC,id DESC);
CREATE FUNCTION mdm_apple_ade_sso_repair_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'ADE provider repair history is immutable'; END;
$$;
CREATE TRIGGER mdm_apple_ade_sso_repair_immutable BEFORE UPDATE OR DELETE ON mdm_apple_ade_sso_repairs
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_ade_sso_repair_immutable();
