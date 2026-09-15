-- Extend the existing organization catalog without changing Mac approvals.
ALTER TABLE uem_software_versions DROP CONSTRAINT uem_software_versions_kind_check;
ALTER TABLE uem_software_versions ADD CONSTRAINT uem_software_versions_kind_check
 CHECK(kind IN ('macos-pkg','windows-winget','windows-msi','windows-exe'));
ALTER TABLE uem_software_versions DROP CONSTRAINT uem_software_versions_architecture_check;
ALTER TABLE uem_software_versions ADD CONSTRAINT uem_software_versions_architecture_check
 CHECK(architecture IN ('universal','arm64','x86_64','x86'));
ALTER TABLE uem_software_versions ALTER COLUMN artifact_sha256 DROP NOT NULL;
ALTER TABLE uem_software_versions ALTER COLUMN encrypted_url DROP NOT NULL;
ALTER TABLE uem_software_versions ADD COLUMN encrypted_definition BYTEA;
ALTER TABLE uem_software_versions ADD COLUMN windows_metadata JSONB NOT NULL DEFAULT '{}';
ALTER TABLE uem_software_versions ADD COLUMN approval_request_id UUID;
ALTER TABLE uem_software_versions ADD CONSTRAINT uem_software_versions_platform_definition CHECK (
 (kind='macos-pkg' AND architecture<>'x86' AND artifact_sha256 IS NOT NULL AND encrypted_url IS NOT NULL
  AND encrypted_definition IS NULL AND windows_metadata='{}'::jsonb AND approval_request_id IS NULL)
 OR
 (kind IN ('windows-winget','windows-msi','windows-exe') AND architecture<>'universal' AND NOT single_app
  AND encrypted_url IS NULL AND encrypted_definition IS NOT NULL AND octet_length(encrypted_definition) BETWEEN 29 AND 32800
  AND approval_request_id IS NOT NULL AND jsonb_typeof(windows_metadata)='object'
  AND windows_metadata->>'kind' IS NOT NULL AND windows_metadata->>'kind'=kind AND octet_length(windows_metadata::text)<=8192
  AND ((kind='windows-winget' AND artifact_sha256 IS NULL) OR (kind IN ('windows-msi','windows-exe') AND artifact_sha256 IS NOT NULL)))
);
CREATE UNIQUE INDEX uem_software_approval_request ON uem_software_versions(tenant_id,approval_request_id)
 WHERE approval_request_id IS NOT NULL;
CREATE FUNCTION uem_software_version_platform_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM uem_software_packages p WHERE p.id=NEW.package_id AND p.tenant_id=NEW.tenant_id
   AND p.platform=CASE NEW.kind WHEN 'macos-pkg' THEN 'macos' ELSE 'windows' END) THEN
  RAISE EXCEPTION 'Software adapter does not match its package platform';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER uem_software_version_platform_guard BEFORE INSERT ON uem_software_versions
 FOR EACH ROW EXECUTE FUNCTION uem_software_version_platform_guard();
