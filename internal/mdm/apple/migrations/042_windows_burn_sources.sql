-- Explicit Burn revisions retain the same immutable encrypted catalog contract.
-- Existing approvals, preparations and source history are not rewritten.
ALTER TABLE uem_software_versions DROP CONSTRAINT uem_software_versions_kind_check;
ALTER TABLE uem_software_versions ADD CONSTRAINT uem_software_versions_kind_check
 CHECK(kind IN ('macos-pkg','windows-winget','windows-msi','windows-exe','windows-burn'));
ALTER TABLE uem_software_versions DROP CONSTRAINT uem_software_versions_platform_definition;
ALTER TABLE uem_software_versions ADD CONSTRAINT uem_software_versions_platform_definition CHECK (
 (kind='macos-pkg' AND architecture<>'x86' AND artifact_sha256 IS NOT NULL AND encrypted_url IS NOT NULL
  AND encrypted_definition IS NULL AND windows_metadata='{}'::jsonb AND approval_request_id IS NULL)
 OR
 (kind IN ('windows-winget','windows-msi','windows-exe','windows-burn') AND architecture<>'universal' AND NOT single_app
  AND encrypted_url IS NULL AND encrypted_definition IS NOT NULL AND octet_length(encrypted_definition) BETWEEN 29 AND 32800
  AND approval_request_id IS NOT NULL AND jsonb_typeof(windows_metadata)='object'
  AND windows_metadata->>'kind' IS NOT NULL AND windows_metadata->>'kind'=kind AND octet_length(windows_metadata::text)<=8192
  AND ((kind='windows-winget' AND artifact_sha256 IS NULL) OR (kind IN ('windows-msi','windows-exe','windows-burn') AND artifact_sha256 IS NOT NULL))
  AND (kind<>'windows-burn' OR architecture IN ('arm64','x86_64')))
);

CREATE OR REPLACE FUNCTION uem_windows_software_source_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
   AND v.approved_by=NEW.actor AND v.approval_request_id=NEW.id AND v.withdrawn_at IS NULL AND v.kind IN ('windows-msi','windows-burn')
   AND v.tenant_id=s.tenant_id AND v.package_id=s.package_id AND v.name=original.name AND v.version=original.version
   AND v.architecture=original.architecture AND v.windows_metadata->'detection'=original.windows_metadata->'detection'
 ) THEN
  RAISE EXCEPTION 'WinGet approval requires its exact reviewed source and derived installer revision';
 END IF;
 END IF;
 RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION uem_windows_software_request_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'Windows software preparation history cannot be deleted'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.status<>'prepared' OR NOT EXISTS(SELECT 1 FROM uem_software_versions WHERE id=NEW.version_id AND tenant_id=NEW.tenant_id AND kind IN ('windows-winget','windows-msi','windows-exe','windows-burn') AND withdrawn_at IS NULL) THEN
   RAISE EXCEPTION 'Windows software preparation requires an approved Windows revision';
  END IF;
 ELSIF (to_jsonb(NEW)-'status'-'completed_at') IS DISTINCT FROM (to_jsonb(OLD)-'status'-'completed_at')
   OR OLD.status<>'prepared' OR NEW.status NOT IN ('dispatched','cancelled','expired') THEN
  RAISE EXCEPTION 'Windows software preparation intent and terminal history are immutable';
 ELSIF NEW.status='dispatched' AND NOT EXISTS(SELECT 1 FROM uem_windows_software_dispatches WHERE preparation_id=NEW.id) THEN
  RAISE EXCEPTION 'Windows preparation cannot execute without explicit dispatch';
 ELSIF NEW.status IN ('cancelled','expired') AND EXISTS(SELECT 1 FROM uem_windows_software_dispatches WHERE preparation_id=NEW.id) THEN
  RAISE EXCEPTION 'Dispatched Windows preparation cannot become unsent';
 END IF;
 RETURN NEW;
END;
$$;
