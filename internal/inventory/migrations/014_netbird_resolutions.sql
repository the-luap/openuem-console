-- The admission row commits independently before a release RPC. Neither table
-- has a foreign key to the request locked by the coordinating transaction.
CREATE TABLE uem_netbird_resolutions (
 request_id UUID PRIMARY KEY,
 id UUID NOT NULL UNIQUE CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 device_id TEXT NOT NULL,
 tenant_id BIGINT NOT NULL CHECK(tenant_id>0),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 individual BOOLEAN NOT NULL,
 command_hash TEXT NOT NULL CHECK(command_hash ~ '^[0-9a-f]{64}$'),
 revision TEXT NOT NULL CHECK(revision ~ '^[0-9a-f]{64}$'),
 kind TEXT NOT NULL CHECK(kind IN ('release','acknowledge')),
 control JSONB NOT NULL CHECK(jsonb_typeof(control)='object' AND octet_length(control::text)<=8192),
 control_hash TEXT NOT NULL CHECK(control_hash ~ '^[0-9a-f]{64}$'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK(control->>'reference_id'=request_id::text AND control->>'command_hash'=command_hash),
 CHECK(control->>'device_id'=device_id AND control->'tenant_id'=to_jsonb(tenant_id) AND control->'site_id'=to_jsonb(site_id) AND control->'individual'=to_jsonb(individual)),
 CHECK((kind='release' AND control->>'kind'='release' AND control->>'request_id'=id::text) OR (kind='acknowledge' AND control->>'kind'='receipt'))
);
CREATE FUNCTION uem_netbird_resolution_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird resolution evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_resolution_immutable BEFORE UPDATE OR DELETE ON uem_netbird_resolutions FOR EACH ROW EXECUTE FUNCTION uem_netbird_resolution_immutable();

CREATE TABLE uem_netbird_resolution_evidence (
 request_id UUID PRIMARY KEY,
 resolution_id UUID NOT NULL UNIQUE,
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 control JSONB NOT NULL CHECK(jsonb_typeof(control)='object' AND octet_length(control::text)<=8192),
 response JSONB NOT NULL CHECK(jsonb_typeof(response)='object' AND octet_length(response::text)<=8192),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION uem_netbird_resolution_evidence_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird resolution evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_resolution_evidence_immutable BEFORE UPDATE OR DELETE ON uem_netbird_resolution_evidence FOR EACH ROW EXECUTE FUNCTION uem_netbird_resolution_evidence_immutable();

-- Application decoding additionally validates canonical controls, full SHA-256
-- correlation and live deadlines. This guard rejects unmatched/partial evidence
-- and prevents a database-only release from opening the command barrier.
CREATE FUNCTION uem_netbird_resolution_evidence_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_operations%ROWTYPE; d uem_netbird_resolutions%ROWTYPE; c JSONB; p JSONB; state JSONB; receipt JSONB;
BEGIN
 SELECT * INTO r FROM uem_netbird_operations WHERE id=NEW.request_id;
 IF NOT FOUND OR r.status<>'unconfirmed' OR r.released_at IS NOT NULL THEN RAISE EXCEPTION 'NetBird resolution requires an uncertain request'; END IF;
 SELECT * INTO d FROM uem_netbird_resolutions WHERE request_id=r.id AND id=NEW.resolution_id AND device_id=r.device_id AND tenant_id=r.tenant_id AND site_id=r.site_id AND individual=r.individual;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM uem_netbird_operation_attempts WHERE request_id=r.id AND command_hash=d.command_hash) THEN RAISE EXCEPTION 'NetBird resolution admission is missing'; END IF;
 c:=NEW.control; p:=NEW.response;
 IF c IS DISTINCT FROM jsonb_build_object('version',1,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',c->'request_id','kind',c->'kind','reference_id',r.id::text,'command_hash',d.command_hash,'issued_at',c->'issued_at','expires_at',c->'expires_at')
 OR jsonb_typeof(c->'certificate_hash') IS DISTINCT FROM 'string'
 OR (r.individual AND NOT coalesce(c->>'certificate_hash' ~ '^[0-9a-f]{64}$',false))
 OR (NOT r.individual AND c->>'certificate_hash'<>'')
 OR NOT coalesce(c->>'request_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false)
 OR NOT coalesce(c->>'kind' IN ('receipt','release'),false)
 OR (c->>'kind'='release' AND (d.kind<>'release' OR c IS DISTINCT FROM d.control))
 OR jsonb_typeof(c->'issued_at') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'expires_at') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'NetBird resolution control is invalid'; END IF;
 IF NOT ((c->>'expires_at')::timestamptz>(c->>'issued_at')::timestamptz AND (c->>'expires_at')::timestamptz<=(c->>'issued_at')::timestamptz+interval '10 seconds') THEN RAISE EXCEPTION 'NetBird resolution deadline is invalid'; END IF;
 state:=jsonb_build_object('status','','revision','','remaining',0,'pending_id','','pending_hash','','can_release',false);
 receipt:=jsonb_build_object('version',1,'request_id',r.id::text,'device_id',r.device_id,'revision',r.revision,'command_hash',d.command_hash,'operation',r.operation,'status',CASE WHEN d.kind='acknowledge' THEN 'completed' ELSE 'unconfirmed' END);
 IF p IS DISTINCT FROM jsonb_build_object('version',1,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',c->'request_id','request_hash',p->'request_hash','kind',c->'kind','outcome','ok','state',state,'receipt',receipt,'release_id',CASE WHEN d.kind='release' THEN d.id::text ELSE '' END)
 OR NOT coalesce(p->>'request_hash' ~ '^[0-9a-f]{64}$',false)
 THEN RAISE EXCEPTION 'NetBird resolution response is invalid'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_resolution_evidence_valid BEFORE INSERT ON uem_netbird_resolution_evidence FOR EACH ROW EXECUTE FUNCTION uem_netbird_resolution_evidence_valid();

CREATE FUNCTION uem_netbird_resolution_required() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.released_at IS NOT NULL AND (TG_OP='INSERT' OR OLD.released_at IS NULL) THEN
  IF NOT EXISTS(SELECT 1 FROM uem_netbird_resolution_evidence e JOIN uem_netbird_resolutions d ON d.id=e.resolution_id AND d.request_id=e.request_id WHERE e.request_id=NEW.id AND e.actor=NEW.released_by) THEN
   RAISE EXCEPTION 'NetBird release requires retained agent evidence';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_resolution_required BEFORE INSERT OR UPDATE ON uem_netbird_operations FOR EACH ROW EXECUTE FUNCTION uem_netbird_resolution_required();

DO $$
DECLARE guard RECORD; found INTEGER:=0;
BEGIN
 FOR guard IN SELECT conname FROM pg_catalog.pg_constraint WHERE conrelid='uem_netbird_operations_audit'::regclass AND contype='c' AND pg_catalog.pg_get_constraintdef(oid) LIKE '%inventory.netbird.review%' LOOP
  found:=found+1;
  EXECUTE format('ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT %I',guard.conname);
 END LOOP;
 IF found<>1 THEN RAISE EXCEPTION 'NetBird audit validation is incomplete'; END IF;
END $$;
ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT uem_netbird_audit_action CHECK(action IN ('inventory.netbird.review','inventory.netbird.request','inventory.netbird.read','inventory.netbird.attempt','inventory.netbird.completed','inventory.netbird.stopped','inventory.netbird.unconfirmed','inventory.netbird.release','inventory.netbird.resolution.review','inventory.netbird.resolution.attempt','inventory.netbird.resolution.observe'));
