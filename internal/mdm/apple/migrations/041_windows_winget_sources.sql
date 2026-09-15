-- Exact source captures and their derived approvals are separate immutable facts.
-- Neither insertion creates a device preparation or executable delivery task.
CREATE TABLE uem_windows_software_sources (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 package_id UUID NOT NULL,
 source_version_id UUID NOT NULL,
 actor TEXT NOT NULL CHECK(length(actor)>0),
 source_commit TEXT NOT NULL CHECK(source_commit ~ '^[0-9a-f]{40}$'),
 manifest_path TEXT NOT NULL CHECK(length(manifest_path) BETWEEN 1 AND 2048),
 manifest_sha256 TEXT NOT NULL CHECK(manifest_sha256 ~ '^[0-9a-f]{64}$'),
 encrypted_snapshot BYTEA NOT NULL CHECK(octet_length(encrypted_snapshot) BETWEEN 29 AND 1048576),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL,
 UNIQUE(tenant_id,package_id,source_version_id,id),
 FOREIGN KEY(tenant_id,package_id,source_version_id) REFERENCES uem_software_versions(tenant_id,package_id,id),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '1 hour')
);
CREATE INDEX uem_windows_software_source_history ON uem_windows_software_sources(tenant_id,source_version_id,created_at DESC,id);

CREATE TABLE uem_windows_software_source_approvals (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 package_id UUID NOT NULL,
 source_version_id UUID NOT NULL,
 source_id UUID NOT NULL UNIQUE,
 version_id UUID NOT NULL UNIQUE,
 actor TEXT NOT NULL CHECK(length(actor)>0),
 installer_index INTEGER NOT NULL CHECK(installer_index BETWEEN 0 AND 255),
 review_hash TEXT NOT NULL CHECK(review_hash ~ '^[0-9a-f]{64}$'),
 approved_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,package_id,source_version_id,source_id) REFERENCES uem_windows_software_sources(tenant_id,package_id,source_version_id,id),
 FOREIGN KEY(tenant_id,package_id,version_id) REFERENCES uem_software_versions(tenant_id,package_id,id),
 CHECK(source_version_id<>version_id)
);

CREATE FUNCTION uem_windows_software_source_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'WinGet source and approval history is immutable'; END IF;
 IF NOT EXISTS(SELECT 1 FROM uem_software_versions v WHERE v.id=NEW.source_version_id AND v.tenant_id=NEW.tenant_id AND v.package_id=NEW.package_id AND v.kind='windows-winget' AND v.withdrawn_at IS NULL) THEN
  RAISE EXCEPTION 'WinGet source requires its approved original coordinate';
 END IF;
 IF TG_TABLE_NAME='uem_windows_software_source_approvals' THEN
 IF NOT EXISTS(
   SELECT 1 FROM uem_windows_software_sources s JOIN uem_software_versions v ON v.id=NEW.version_id
   JOIN uem_software_versions original ON original.id=s.source_version_id
   WHERE s.id=NEW.source_id AND s.tenant_id=NEW.tenant_id AND s.package_id=NEW.package_id
   AND s.source_version_id=NEW.source_version_id AND s.actor=NEW.actor AND s.expires_at>clock_timestamp()
   AND v.approved_by=NEW.actor AND v.approval_request_id=NEW.id AND v.withdrawn_at IS NULL AND v.kind='windows-msi'
   AND v.tenant_id=s.tenant_id AND v.package_id=s.package_id AND v.name=original.name AND v.version=original.version
   AND v.architecture=original.architecture AND v.windows_metadata->'detection'=original.windows_metadata->'detection'
 ) THEN
  RAISE EXCEPTION 'WinGet approval requires its exact reviewed source and derived MSI revision';
 END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER uem_windows_software_source_guard BEFORE INSERT OR UPDATE OR DELETE ON uem_windows_software_sources
 FOR EACH ROW EXECUTE FUNCTION uem_windows_software_source_guard();
CREATE TRIGGER uem_windows_software_source_truncate BEFORE TRUNCATE ON uem_windows_software_sources
 FOR EACH STATEMENT EXECUTE FUNCTION uem_windows_software_source_guard();
CREATE TRIGGER uem_windows_software_source_approval_guard BEFORE INSERT OR UPDATE OR DELETE ON uem_windows_software_source_approvals
 FOR EACH ROW EXECUTE FUNCTION uem_windows_software_source_guard();
CREATE TRIGGER uem_windows_software_source_approval_truncate BEFORE TRUNCATE ON uem_windows_software_source_approvals
 FOR EACH STATEMENT EXECUTE FUNCTION uem_windows_software_source_guard();
