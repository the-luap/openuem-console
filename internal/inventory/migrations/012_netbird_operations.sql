-- Permanent generations invalidate reviews after device recreation, scope ABA
-- or eligibility/platform changes. Reported network metadata is not identity.
CREATE TABLE uem_netbird_device_bindings (
 device_id TEXT PRIMARY KEY,
 revision UUID NOT NULL DEFAULT gen_random_uuid()
);
INSERT INTO uem_netbird_device_bindings(device_id) SELECT oid FROM agents;
CREATE FUNCTION uem_netbird_agent_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' OR OLD.os IS DISTINCT FROM NEW.os OR
    (OLD.agent_status IN ('Enabled','No contact')) IS DISTINCT FROM (NEW.agent_status IN ('Enabled','No contact')) THEN
  INSERT INTO uem_netbird_device_bindings(device_id) VALUES(NEW.oid)
   ON CONFLICT(device_id) DO UPDATE SET revision=gen_random_uuid();
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_agent_binding AFTER INSERT OR UPDATE OF os,agent_status ON agents FOR EACH ROW EXECUTE FUNCTION uem_netbird_agent_binding();
CREATE FUNCTION uem_netbird_scope_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN
  INSERT INTO uem_netbird_device_bindings(device_id) VALUES(OLD.agent_id)
   ON CONFLICT(device_id) DO UPDATE SET revision=gen_random_uuid();
 END IF;
 IF TG_OP<>'DELETE' THEN
  INSERT INTO uem_netbird_device_bindings(device_id) VALUES(NEW.agent_id)
   ON CONFLICT(device_id) DO UPDATE SET revision=gen_random_uuid();
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER uem_netbird_scope_binding AFTER INSERT OR UPDATE OR DELETE ON site_agents FOR EACH ROW EXECUTE FUNCTION uem_netbird_scope_binding();
CREATE FUNCTION uem_netbird_site_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.tenant_sites IS DISTINCT FROM NEW.tenant_sites THEN
  INSERT INTO uem_netbird_device_bindings(device_id) SELECT agent_id FROM site_agents WHERE site_id=NEW.id
   ON CONFLICT(device_id) DO UPDATE SET revision=gen_random_uuid();
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_site_binding AFTER UPDATE OF tenant_sites ON sites FOR EACH ROW EXECUTE FUNCTION uem_netbird_site_binding();
CREATE FUNCTION uem_netbird_installation_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND NEW.installed IS NOT DISTINCT FROM OLD.installed AND NEW.agent_netbird IS NOT DISTINCT FROM OLD.agent_netbird THEN RETURN NULL; END IF;
 IF TG_OP<>'INSERT' AND OLD.agent_netbird IS NOT NULL THEN
  INSERT INTO uem_netbird_device_bindings(device_id) VALUES(OLD.agent_netbird)
   ON CONFLICT(device_id) DO UPDATE SET revision=gen_random_uuid();
 END IF;
 IF TG_OP<>'DELETE' AND NEW.agent_netbird IS NOT NULL THEN
  INSERT INTO uem_netbird_device_bindings(device_id) VALUES(NEW.agent_netbird)
   ON CONFLICT(device_id) DO UPDATE SET revision=gen_random_uuid();
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER uem_netbird_installation_binding AFTER INSERT OR DELETE OR UPDATE OF installed,agent_netbird ON netbirds FOR EACH ROW EXECUTE FUNCTION uem_netbird_installation_binding();

CREATE TABLE uem_netbird_operations (
 id UUID PRIMARY KEY,
 device_id TEXT NOT NULL CHECK(device_id ~ '^[A-Za-z0-9_-]{1,255}$'),
 tenant_id BIGINT NOT NULL CHECK(tenant_id>0),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 individual BOOLEAN NOT NULL,
 operation TEXT NOT NULL CHECK(operation IN ('up','down','switchprofile')),
 profile TEXT NOT NULL DEFAULT '' CHECK(octet_length(profile)<=256),
 revision TEXT NOT NULL CHECK(revision ~ '^[0-9a-f]{64}$'),
 status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','completed','stopped','unconfirmed')),
 reason TEXT NOT NULL DEFAULT '' CHECK(reason IN ('','expired','mode_changed','not_authorized','source_changed','cancelled','delivery_unconfirmed')),
 result JSONB CHECK(result IS NULL OR octet_length(result::text)<=1048576),
 requested_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp()+interval '2 minutes',
 finished_at TIMESTAMPTZ,
 released_at TIMESTAMPTZ,
 released_by TEXT CHECK(length(released_by) BETWEEN 1 AND 255),
 CHECK((operation='switchprofile')=(profile<>'')),
 CHECK((status='queued')=(finished_at IS NULL)),
 CHECK((status='completed')=(result IS NOT NULL)),
 CHECK((status IN ('queued','completed'))=(reason='')),
 CHECK((status='unconfirmed')=(reason='delivery_unconfirmed')),
 CHECK(result IS NULL OR result=jsonb_build_object('request_id',id::text,'device_id',device_id,'revision',revision,'operation',operation,'success',true)),
 CHECK(expires_at>requested_at AND expires_at<=requested_at+interval '2 minutes'),
 CHECK((released_at IS NULL)=(released_by IS NULL)),
 CHECK(released_at IS NULL OR status='unconfirmed')
);
CREATE UNIQUE INDEX uem_netbird_operations_barrier ON uem_netbird_operations(device_id) WHERE status='queued' OR (status='unconfirmed' AND released_at IS NULL);
CREATE INDEX uem_netbird_operations_due ON uem_netbird_operations(requested_at,id) WHERE status='queued';
CREATE INDEX uem_netbird_operations_history ON uem_netbird_operations(tenant_id,site_id,device_id,requested_at DESC,id DESC);

-- A separate committed receipt survives dispatch rollback and audit retention.
-- No FK may block publication while the request row is locked by dispatch.
CREATE TABLE uem_netbird_operation_attempts (
 request_id UUID PRIMARY KEY,
 device_id TEXT NOT NULL,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 actor TEXT NOT NULL,
 operation TEXT NOT NULL,
 revision TEXT NOT NULL CHECK(revision ~ '^[0-9a-f]{64}$'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION uem_netbird_attempt_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird attempt receipts are permanent'; END $$;
CREATE TRIGGER uem_netbird_attempt_immutable BEFORE UPDATE OR DELETE ON uem_netbird_operation_attempts FOR EACH ROW EXECUTE FUNCTION uem_netbird_attempt_immutable();

CREATE TABLE uem_netbird_operations_audit (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 request_id UUID,
 tenant_id BIGINT NOT NULL CHECK(tenant_id>0),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 action TEXT NOT NULL CHECK(action IN ('inventory.netbird.review','inventory.netbird.request','inventory.netbird.read','inventory.netbird.attempt','inventory.netbird.completed','inventory.netbird.stopped','inventory.netbird.unconfirmed','inventory.netbird.release')),
 resource_id TEXT NOT NULL,
 result TEXT NOT NULL CHECK(result IN ('recorded','success','cancelled','failure')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX uem_netbird_operations_audit_scope ON uem_netbird_operations_audit(tenant_id,created_at DESC,id DESC);
CREATE INDEX uem_netbird_operations_audit_time ON uem_netbird_operations_audit(created_at DESC,id DESC);

CREATE FUNCTION uem_netbird_operation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'NetBird request receipts are permanent';
 END IF;
 IF OLD.id IS DISTINCT FROM NEW.id OR OLD.device_id IS DISTINCT FROM NEW.device_id OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.site_id IS DISTINCT FROM NEW.site_id OR OLD.actor IS DISTINCT FROM NEW.actor OR OLD.individual IS DISTINCT FROM NEW.individual OR OLD.operation IS DISTINCT FROM NEW.operation OR OLD.profile IS DISTINCT FROM NEW.profile OR OLD.revision IS DISTINCT FROM NEW.revision OR OLD.requested_at IS DISTINCT FROM NEW.requested_at OR OLD.expires_at IS DISTINCT FROM NEW.expires_at THEN
  RAISE EXCEPTION 'NetBird request identity is immutable';
 END IF;
 IF OLD.status<>'queued' AND (OLD.status IS DISTINCT FROM NEW.status OR OLD.reason IS DISTINCT FROM NEW.reason OR OLD.result IS DISTINCT FROM NEW.result OR OLD.finished_at IS DISTINCT FROM NEW.finished_at) THEN
  RAISE EXCEPTION 'NetBird outcomes are immutable';
 END IF;
 IF OLD.released_at IS NOT NULL AND (OLD.released_at IS DISTINCT FROM NEW.released_at OR OLD.released_by IS DISTINCT FROM NEW.released_by) THEN
  RAISE EXCEPTION 'NetBird resolution is immutable';
 END IF;
 IF OLD.status='queued' AND NEW.status<>'queued' THEN
  IF (NEW.status<>'stopped') IS DISTINCT FROM EXISTS(SELECT 1 FROM uem_netbird_operation_attempts a WHERE a.request_id=NEW.id AND a.device_id=NEW.device_id AND a.tenant_id=NEW.tenant_id AND a.site_id=NEW.site_id AND a.actor=NEW.actor AND a.operation=NEW.operation AND a.revision=NEW.revision) THEN
   RAISE EXCEPTION 'NetBird outcome does not match its attempt receipt';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_operation_immutable BEFORE UPDATE OR DELETE ON uem_netbird_operations FOR EACH ROW EXECUTE FUNCTION uem_netbird_operation_immutable();
