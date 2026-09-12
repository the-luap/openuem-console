-- Existing preparations remain inert. Only a fresh, explicitly authorized
-- dispatch transaction can attach a signed registry task and close preparation.
ALTER TABLE uem_windows_software_requests DROP CONSTRAINT uem_windows_software_requests_status_check;
ALTER TABLE uem_windows_software_requests ADD CONSTRAINT uem_windows_software_requests_status_check CHECK(status IN ('prepared','dispatched','cancelled','expired'));
ALTER TABLE uem_windows_software_requests ADD UNIQUE(tenant_id,site_id,agent_id,version_id,id);

CREATE TABLE uem_windows_software_dispatches (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 agent_id UUID NOT NULL,
 version_id UUID NOT NULL,
 preparation_id UUID NOT NULL UNIQUE,
 actor TEXT NOT NULL CHECK(length(actor)>0),
 review_hash TEXT NOT NULL CHECK(review_hash ~ '^[a-f0-9]{64}$'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL,
 FOREIGN KEY(tenant_id,site_id,agent_id,version_id,preparation_id) REFERENCES uem_windows_software_requests(tenant_id,site_id,agent_id,version_id,id),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '1 hour')
);
CREATE FUNCTION uem_windows_software_dispatch_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Windows software dispatch history is immutable'; END IF;
 IF NOT EXISTS(SELECT 1 FROM uem_windows_software_requests r JOIN uem_agent_software_tasks t
   ON t.id=NEW.id AND t.preparation_id=r.id AND t.tenant_id=r.tenant_id AND t.site_id=r.site_id
   AND t.device_id=r.agent_id AND t.revision_id=r.version_id AND t.certificate_hash=r.certificate_hash
   WHERE r.id=NEW.preparation_id AND r.status='prepared' AND r.tenant_id=NEW.tenant_id
   AND r.site_id=NEW.site_id AND r.agent_id=NEW.agent_id AND r.version_id=NEW.version_id
   AND t.actor=NEW.actor AND t.status='pending' AND t.expires_at=NEW.expires_at
   AND NEW.expires_at<=r.expires_at AND NEW.expires_at>clock_timestamp()) THEN
  RAISE EXCEPTION 'Windows dispatch requires the matching current signed task and preparation';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER uem_windows_software_dispatch_guard BEFORE INSERT OR UPDATE OR DELETE ON uem_windows_software_dispatches FOR EACH ROW EXECUTE FUNCTION uem_windows_software_dispatch_guard();
CREATE TRIGGER uem_windows_software_dispatch_truncate BEFORE TRUNCATE ON uem_windows_software_dispatches FOR EACH STATEMENT EXECUTE FUNCTION uem_windows_software_dispatch_guard();
CREATE FUNCTION uem_windows_software_dispatch_committed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM uem_windows_software_requests WHERE id=NEW.preparation_id AND status='dispatched') THEN
  RAISE EXCEPTION 'Windows dispatch must close its preparation in the same transaction';
 END IF;
 RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER uem_windows_software_dispatch_committed AFTER INSERT ON uem_windows_software_dispatches DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION uem_windows_software_dispatch_committed();

CREATE OR REPLACE FUNCTION uem_windows_software_request_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'Windows software preparation history cannot be deleted'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.status<>'prepared' OR NOT EXISTS(SELECT 1 FROM uem_software_versions WHERE id=NEW.version_id AND tenant_id=NEW.tenant_id AND kind IN ('windows-winget','windows-msi','windows-exe') AND withdrawn_at IS NULL) THEN
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
