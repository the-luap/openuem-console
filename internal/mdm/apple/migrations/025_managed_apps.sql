-- Approved artifact identities are separate from the upstream searchable source
-- index. The catalog supports multiple platform adapters; this migration adds
-- the first native macOS device-channel adapter.
CREATE TABLE uem_software_packages (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES tenants(id),
 platform TEXT NOT NULL CHECK(platform IN ('macos','windows','linux')),
 identifier TEXT NOT NULL CHECK(length(identifier) BETWEEN 1 AND 255),
 UNIQUE(tenant_id,platform,identifier),
 UNIQUE(tenant_id,id)
);
CREATE TABLE uem_software_versions (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 package_id UUID NOT NULL,
 name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 255),
 version TEXT NOT NULL CHECK(length(version) BETWEEN 1 AND 128),
 kind TEXT NOT NULL CHECK(kind IN ('macos-pkg')),
 architecture TEXT NOT NULL CHECK(architecture IN ('universal','arm64','x86_64')),
 minimum_os TEXT NOT NULL,
 artifact_sha256 TEXT NOT NULL CHECK(artifact_sha256 ~ '^[a-f0-9]{64}$'),
 encrypted_url BYTEA NOT NULL CHECK(octet_length(encrypted_url)>28),
 single_app BOOLEAN NOT NULL,
 approved_by TEXT NOT NULL,
 approved_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 withdrawn_at TIMESTAMPTZ,
 UNIQUE(tenant_id,package_id,id),
 FOREIGN KEY(tenant_id,package_id) REFERENCES uem_software_packages(tenant_id,id)
);
CREATE INDEX uem_software_versions_catalog ON uem_software_versions(tenant_id,approved_at DESC,id);
CREATE FUNCTION uem_software_package_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'Software package identities are immutable'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER uem_software_package_immutable BEFORE UPDATE ON uem_software_packages
 FOR EACH ROW EXECUTE FUNCTION uem_software_package_immutable();
CREATE FUNCTION uem_software_version_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-'withdrawn_at') IS DISTINCT FROM (to_jsonb(OLD)-'withdrawn_at')
    OR (OLD.withdrawn_at IS NOT NULL AND NEW.withdrawn_at IS DISTINCT FROM OLD.withdrawn_at) THEN
  RAISE EXCEPTION 'Approved software artifacts are immutable and withdrawal is permanent';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER uem_software_version_immutable BEFORE UPDATE ON uem_software_versions
 FOR EACH ROW EXECUTE FUNCTION uem_software_version_immutable();

CREATE TABLE mdm_apple_app_assignments (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 package_id UUID NOT NULL,
 version_id UUID NOT NULL,
 current_attempt_id UUID,
 desired TEXT NOT NULL CHECK(desired IN ('present','absent')),
 status TEXT NOT NULL CHECK(status IN ('queued','sent','not_now','verifying','verified','drifted','failed','uncertain','expired','cancelled','not_managed')),
 next_check_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(device_id,package_id),
 UNIQUE(tenant_id,device_id,package_id,id),
 FOREIGN KEY(tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id),
 FOREIGN KEY(tenant_id,package_id,version_id) REFERENCES uem_software_versions(tenant_id,package_id,id)
);
CREATE INDEX mdm_apple_app_assignments_due ON mdm_apple_app_assignments(next_check_at,device_id)
 WHERE status NOT IN ('cancelled','expired','not_managed');
CREATE TABLE mdm_apple_app_attempts (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 package_id UUID NOT NULL,
 assignment_id UUID NOT NULL,
 version_id UUID NOT NULL,
 operation TEXT NOT NULL CHECK(operation IN ('install','remove')),
 options JSONB NOT NULL CHECK(jsonb_typeof(options)='object'),
 status TEXT NOT NULL CHECK(status IN ('queued','sent','not_now','verifying','verified','drifted','failed','uncertain','expired','cancelled','not_managed')),
 requested_by TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 dispatched_at TIMESTAMPTZ,
 accepted_at TIMESTAMPTZ,
 managed_state TEXT NOT NULL DEFAULT 'unknown',
 managed_at TIMESTAMPTZ,
 installed_state TEXT NOT NULL DEFAULT 'unknown',
 installed_version TEXT NOT NULL DEFAULT '',
 installed_at TIMESTAMPTZ,
 error TEXT NOT NULL DEFAULT '',
 UNIQUE(assignment_id,id),
 UNIQUE(tenant_id,device_id,id),
 FOREIGN KEY(tenant_id,device_id,package_id,assignment_id) REFERENCES mdm_apple_app_assignments(tenant_id,device_id,package_id,id),
 FOREIGN KEY(tenant_id,package_id,version_id) REFERENCES uem_software_versions(tenant_id,package_id,id)
);
CREATE UNIQUE INDEX mdm_apple_app_attempt_one_active ON mdm_apple_app_attempts(assignment_id)
 WHERE status IN ('queued','sent','not_now','verifying','uncertain');
ALTER TABLE mdm_apple_app_assignments ADD CONSTRAINT mdm_apple_app_current_attempt
 FOREIGN KEY(id,current_attempt_id) REFERENCES mdm_apple_app_attempts(assignment_id,id);
ALTER TABLE mdm_apple_commands ADD CONSTRAINT mdm_apple_commands_device_identity UNIQUE(tenant_id,device_id,id);
CREATE TABLE mdm_apple_app_commands (
 command_id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 attempt_id UUID NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('install','remove','managed','installed')),
 FOREIGN KEY(tenant_id,device_id,command_id) REFERENCES mdm_apple_commands(tenant_id,device_id,id),
 FOREIGN KEY(tenant_id,device_id,attempt_id) REFERENCES mdm_apple_app_attempts(tenant_id,device_id,id)
);
CREATE INDEX mdm_apple_app_commands_attempt ON mdm_apple_app_commands(attempt_id,command_id);
CREATE UNIQUE INDEX mdm_apple_app_one_mutation_command ON mdm_apple_app_commands(attempt_id)
 WHERE kind IN ('install','remove');
ALTER TABLE mdm_apple_commands ADD COLUMN managed_app BOOLEAN NOT NULL DEFAULT false;
CREATE FUNCTION mdm_apple_app_intent_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.tenant_id,NEW.device_id,NEW.package_id,NEW.assignment_id,NEW.version_id,NEW.operation,NEW.options,NEW.requested_by,NEW.created_at)
    IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.device_id,OLD.package_id,OLD.assignment_id,OLD.version_id,OLD.operation,OLD.options,OLD.requested_by,OLD.created_at) THEN
  RAISE EXCEPTION 'Application operation intent is immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_app_intent_immutable BEFORE UPDATE ON mdm_apple_app_attempts
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_app_intent_immutable();
CREATE FUNCTION mdm_apple_app_command_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND NEW IS DISTINCT FROM OLD THEN
  RAISE EXCEPTION 'Application command bindings are immutable';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM mdm_apple_commands c JOIN mdm_apple_app_attempts t ON t.id=NEW.attempt_id
     WHERE c.id=NEW.command_id AND c.managed_app AND c.tenant_id=NEW.tenant_id AND c.device_id=NEW.device_id
     AND t.tenant_id=NEW.tenant_id AND t.device_id=NEW.device_id
     AND c.request_type=CASE NEW.kind WHEN 'install' THEN 'InstallEnterpriseApplication' WHEN 'remove' THEN 'RemoveApplication' WHEN 'managed' THEN 'ManagedApplicationList' WHEN 'installed' THEN 'InstalledApplicationList' END
     AND (NEW.kind IN ('managed','installed') OR NEW.kind=t.operation)) THEN
  RAISE EXCEPTION 'Application command does not match its device and operation';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_app_command_guard BEFORE INSERT OR UPDATE ON mdm_apple_app_commands
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_app_command_guard();
