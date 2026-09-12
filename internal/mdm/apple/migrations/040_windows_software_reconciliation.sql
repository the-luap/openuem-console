-- A separately reviewed read-only check never rewrites an executable request.
-- Registry tables may be migrated after this catalog; the insertion guard is
-- evaluated only when both components admit a real reconciliation transaction.
CREATE TABLE uem_windows_software_reconciliations (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 agent_id UUID NOT NULL,
 version_id UUID NOT NULL,
 preparation_id UUID NOT NULL,
 original_task_id UUID NOT NULL REFERENCES uem_windows_software_dispatches(id),
 actor TEXT NOT NULL CHECK(length(actor)>0),
 review_hash TEXT NOT NULL CHECK(review_hash ~ '^[a-f0-9]{64}$'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL,
 FOREIGN KEY(tenant_id,site_id,agent_id,version_id,preparation_id)
  REFERENCES uem_windows_software_requests(tenant_id,site_id,agent_id,version_id,id),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '1 hour')
);
CREATE INDEX uem_windows_software_reconciliation_history ON uem_windows_software_reconciliations(tenant_id,site_id,preparation_id,created_at,id);

CREATE FUNCTION uem_windows_software_reconciliation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Windows software reconciliation review history is immutable'; END IF;
 IF NOT EXISTS(SELECT 1 FROM uem_windows_software_dispatches d JOIN uem_agent_software_reconciliations r
   ON r.original_task_id=d.id AND r.tenant_id=d.tenant_id AND r.site_id=d.site_id AND r.device_id=d.agent_id
   WHERE r.id=NEW.id AND d.id=NEW.original_task_id AND d.tenant_id=NEW.tenant_id AND d.site_id=NEW.site_id
   AND d.agent_id=NEW.agent_id AND d.version_id=NEW.version_id AND d.preparation_id=NEW.preparation_id
   AND r.actor=NEW.actor AND r.expires_at=NEW.expires_at AND r.status='pending' AND r.delivered_at IS NULL
   AND r.expires_at>clock_timestamp()) THEN
  RAISE EXCEPTION 'Windows reconciliation review requires its exact signed read-only task';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER uem_windows_software_reconciliation_guard BEFORE INSERT OR UPDATE OR DELETE ON uem_windows_software_reconciliations
 FOR EACH ROW EXECUTE FUNCTION uem_windows_software_reconciliation_guard();
CREATE TRIGGER uem_windows_software_reconciliation_truncate BEFORE TRUNCATE ON uem_windows_software_reconciliations
 FOR EACH STATEMENT EXECUTE FUNCTION uem_windows_software_reconciliation_guard();
