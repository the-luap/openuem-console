-- Durable operator intent; this schema deliberately has no deliverable state.
-- A future adapter must add explicit dispatch admission and cannot treat these
-- preparations as proof of installer execution or observed application state.
CREATE TABLE uem_windows_software_requests (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL CHECK(site_id>0),
 agent_id UUID NOT NULL,
 certificate_hash TEXT NOT NULL CHECK(certificate_hash ~ '^[a-f0-9]{64}$'),
 package_id UUID NOT NULL,
 version_id UUID NOT NULL,
 request_id UUID NOT NULL,
 operation TEXT NOT NULL CHECK(operation IN ('install','remove')),
 actor TEXT NOT NULL CHECK(length(actor)>0),
 status TEXT NOT NULL DEFAULT 'prepared' CHECK(status IN ('prepared','cancelled','expired')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL,
 completed_at TIMESTAMPTZ,
 UNIQUE(tenant_id,request_id),
 FOREIGN KEY(tenant_id,package_id,version_id) REFERENCES uem_software_versions(tenant_id,package_id,id),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '24 hours'),
 CHECK((status='prepared')=(completed_at IS NULL))
);
-- Serialize all pending software intent on an endpoint, including approvals
-- with different catalog identifiers but the same native product identity.
CREATE UNIQUE INDEX uem_windows_software_one_preparation ON uem_windows_software_requests(agent_id) WHERE status='prepared';
CREATE INDEX uem_windows_software_request_history ON uem_windows_software_requests(tenant_id,version_id,created_at DESC,id);
CREATE FUNCTION uem_windows_software_request_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP IN ('DELETE','TRUNCATE') THEN
  RAISE EXCEPTION 'Windows software preparation history cannot be deleted';
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.status<>'prepared' OR NOT EXISTS(SELECT 1 FROM uem_software_versions WHERE id=NEW.version_id AND tenant_id=NEW.tenant_id AND kind IN ('windows-winget','windows-msi','windows-exe') AND withdrawn_at IS NULL) THEN
   RAISE EXCEPTION 'Windows software preparation requires an approved Windows revision';
  END IF;
 ELSIF (to_jsonb(NEW)-'status'-'completed_at') IS DISTINCT FROM (to_jsonb(OLD)-'status'-'completed_at')
   OR OLD.status<>'prepared' OR NEW.status NOT IN ('cancelled','expired') THEN
  RAISE EXCEPTION 'Windows software preparation intent and terminal history are immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER uem_windows_software_request_guard BEFORE INSERT OR UPDATE OR DELETE ON uem_windows_software_requests FOR EACH ROW EXECUTE FUNCTION uem_windows_software_request_guard();
CREATE TRIGGER uem_windows_software_request_truncate BEFORE TRUNCATE ON uem_windows_software_requests FOR EACH STATEMENT EXECUTE FUNCTION uem_windows_software_request_guard();
