-- Connection commands can be permanently withdrawn only through version-two
-- agent evidence. Existing outcomes and resolution identities remain unchanged.
ALTER TABLE uem_netbird_resolutions DROP CONSTRAINT uem_netbird_resolutions_kind_check;
ALTER TABLE uem_netbird_resolutions ADD CONSTRAINT uem_netbird_resolutions_kind_check CHECK(kind IN ('release','acknowledge','withdraw'));
DO $$
DECLARE guard RECORD; found INTEGER:=0;
BEGIN
 FOR guard IN SELECT conname FROM pg_catalog.pg_constraint WHERE conrelid='uem_netbird_resolutions'::regclass AND contype='c' AND pg_catalog.pg_get_constraintdef(oid) LIKE '%control%' AND pg_catalog.pg_get_constraintdef(oid) LIKE '%acknowledge%' LOOP
  found:=found+1;
  EXECUTE format('ALTER TABLE uem_netbird_resolutions DROP CONSTRAINT %I',guard.conname);
 END LOOP;
 IF found<>1 THEN RAISE EXCEPTION 'NetBird control admission is incomplete'; END IF;
END $$;
ALTER TABLE uem_netbird_resolutions ADD CONSTRAINT uem_netbird_resolution_control_kind CHECK((kind IN ('release','withdraw') AND control->>'kind'=kind AND control->>'request_id'=id::text) OR (kind='acknowledge' AND control->>'kind'='receipt'));

CREATE FUNCTION uem_netbird_resolution_intent_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_operations%ROWTYPE; c JSONB; version INTEGER;
BEGIN
 SELECT * INTO r FROM uem_netbird_operations WHERE id=NEW.request_id AND status='unconfirmed' AND released_at IS NULL;
 IF NOT FOUND OR NEW.device_id<>r.device_id OR NEW.tenant_id<>r.tenant_id OR NEW.site_id<>r.site_id OR NEW.individual<>r.individual OR NOT EXISTS(SELECT 1 FROM uem_netbird_operation_attempts WHERE request_id=r.id AND command_hash=NEW.command_hash) THEN RAISE EXCEPTION 'Resolution requires the original uncertain operation'; END IF;
 c:=NEW.control;
 version:=CASE WHEN NEW.kind='withdraw' OR (NEW.kind='acknowledge' AND c->'version'='2'::jsonb) THEN 2 ELSE 1 END;
 IF c IS DISTINCT FROM (jsonb_build_object('version',version,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',c->'request_id','kind',CASE WHEN NEW.kind='acknowledge' THEN 'receipt' ELSE NEW.kind END,'reference_id',r.id::text,'command_hash',NEW.command_hash,'issued_at',c->'issued_at','expires_at',c->'expires_at') || CASE WHEN version=2 THEN jsonb_build_object('revision',r.revision,'operation',r.operation) ELSE '{}'::jsonb END)
 OR (NEW.kind IN ('release','withdraw') AND c->>'request_id' IS DISTINCT FROM NEW.id::text)
 OR jsonb_typeof(c->'certificate_hash') IS DISTINCT FROM 'string'
 OR (r.individual AND NOT coalesce(c->>'certificate_hash' ~ '^[0-9a-f]{64}$',false)) OR (NOT r.individual AND c->>'certificate_hash'<>'')
 OR NOT coalesce(c->>'request_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false)
 OR jsonb_typeof(c->'issued_at') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'expires_at') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'Resolution control is invalid'; END IF;
 IF NOT ((c->>'expires_at')::timestamptz>(c->>'issued_at')::timestamptz AND (c->>'expires_at')::timestamptz<=(c->>'issued_at')::timestamptz+interval '10 seconds') THEN RAISE EXCEPTION 'Resolution deadline is invalid'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_resolution_intent_valid BEFORE INSERT ON uem_netbird_resolutions FOR EACH ROW EXECUTE FUNCTION uem_netbird_resolution_intent_valid();

CREATE OR REPLACE FUNCTION uem_netbird_resolution_retry_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r RECORD; d RECORD; c JSONB; attempted BOOLEAN; operation TEXT;
BEGIN
 IF NEW.family='operation' THEN
  SELECT * INTO r FROM uem_netbird_operations WHERE id=NEW.request_id AND status='unconfirmed' AND released_at IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'Retry requires an unresolved operation'; END IF;
  SELECT * INTO d FROM uem_netbird_resolutions WHERE request_id=r.id AND id=NEW.resolution_id AND device_id=r.device_id AND tenant_id=r.tenant_id AND site_id=r.site_id AND individual=r.individual AND kind IN ('release','withdraw');
  IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM uem_netbird_operation_attempts WHERE request_id=r.id AND command_hash=d.command_hash) THEN RAISE EXCEPTION 'Retry admission is missing'; END IF;
  operation:=r.operation; attempted:=true;
 ELSE
  SELECT * INTO r FROM uem_netbird_registrations WHERE id=NEW.request_id AND status='unconfirmed' AND released_at IS NULL;
  IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM uem_netbird_registration_evidence WHERE request_id=r.id AND kind='absent') THEN RAISE EXCEPTION 'Retry requires retained key absence'; END IF;
  SELECT * INTO d FROM uem_netbird_registration_resolutions WHERE request_id=r.id AND id=NEW.resolution_id AND kind IN ('release','withdraw');
  IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM uem_netbird_registration_attempts WHERE request_id=r.id AND stage='deliver' AND digest=d.command_hash) THEN RAISE EXCEPTION 'Retry admission is missing'; END IF;
  attempted:=EXISTS(SELECT 1 FROM uem_netbird_registration_resolution_attempts WHERE request_id=r.id AND resolution_id=d.id) OR EXISTS(SELECT 1 FROM uem_netbird_resolution_retries WHERE family=NEW.family AND request_id=r.id AND resolution_id=d.id);
  operation:='register';
 END IF;
  IF (d.kind='release' AND (NEW.kind<>'release' OR NOT attempted))
  OR (NEW.kind='withdraw' AND (d.kind<>'withdraw' OR NOT attempted OR EXISTS(SELECT 1 FROM uem_netbird_resolution_retries WHERE family=NEW.family AND request_id=r.id AND kind='release')))
  THEN RAISE EXCEPTION 'Retry phase is invalid'; END IF;
 IF NEW.sequence<>(SELECT coalesce(max(sequence),0)+1 FROM uem_netbird_resolution_retries WHERE family=NEW.family AND request_id=r.id) THEN RAISE EXCEPTION 'Retry sequence is invalid'; END IF;
 c:=NEW.control;
 IF c IS DISTINCT FROM (jsonb_build_object('version',CASE WHEN NEW.kind='withdraw' THEN 2 ELSE 1 END,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',d.id::text,'kind',NEW.kind,'reference_id',r.id::text,'command_hash',d.command_hash,'issued_at',c->'issued_at','expires_at',c->'expires_at') || CASE WHEN NEW.kind='withdraw' THEN jsonb_build_object('revision',r.revision,'operation',operation) ELSE '{}'::jsonb END)
 OR jsonb_typeof(c->'certificate_hash') IS DISTINCT FROM 'string'
 OR (r.individual AND NOT coalesce(c->>'certificate_hash' ~ '^[0-9a-f]{64}$',false)) OR (NOT r.individual AND c->>'certificate_hash'<>'')
 OR jsonb_typeof(c->'issued_at') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'expires_at') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'Retry control is invalid'; END IF;
 IF NOT ((c->>'expires_at')::timestamptz>(c->>'issued_at')::timestamptz AND (c->>'expires_at')::timestamptz<=(c->>'issued_at')::timestamptz+interval '10 seconds') THEN RAISE EXCEPTION 'Retry deadline is invalid'; END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION uem_netbird_resolution_evidence_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_operations%ROWTYPE; d uem_netbird_resolutions%ROWTYPE; c JSONB; p JSONB; state JSONB; receipt JSONB;
BEGIN
 SELECT * INTO r FROM uem_netbird_operations WHERE id=NEW.request_id;
 IF NOT FOUND OR r.status<>'unconfirmed' OR r.released_at IS NOT NULL THEN RAISE EXCEPTION 'NetBird resolution requires an uncertain request'; END IF;
 SELECT * INTO d FROM uem_netbird_resolutions WHERE request_id=r.id AND id=NEW.resolution_id AND device_id=r.device_id AND tenant_id=r.tenant_id AND site_id=r.site_id AND individual=r.individual;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM uem_netbird_operation_attempts WHERE request_id=r.id AND command_hash=d.command_hash) THEN RAISE EXCEPTION 'NetBird resolution admission is missing'; END IF;
 c:=NEW.control; p:=NEW.response;
 IF c IS DISTINCT FROM (jsonb_build_object('version',CASE WHEN c->'version'='2'::jsonb THEN 2 ELSE 1 END,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',c->'request_id','kind',c->'kind','reference_id',r.id::text,'command_hash',d.command_hash,'issued_at',c->'issued_at','expires_at',c->'expires_at') || CASE WHEN c->'version'='2'::jsonb THEN jsonb_build_object('revision',r.revision,'operation',r.operation) ELSE '{}'::jsonb END)
 OR (d.kind='withdraw' AND c->>'kind'<>'release' AND c->'version' IS DISTINCT FROM '2'::jsonb)
 OR (c->>'kind'='release' AND c->'version' IS DISTINCT FROM '1'::jsonb)
 OR jsonb_typeof(c->'certificate_hash') IS DISTINCT FROM 'string'
 OR (r.individual AND NOT coalesce(c->>'certificate_hash' ~ '^[0-9a-f]{64}$',false))
 OR (NOT r.individual AND c->>'certificate_hash'<>'')
 OR NOT coalesce(c->>'request_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false)
 OR NOT coalesce(c->>'kind' IN ('receipt','release','withdraw'),false)
 OR (c->>'kind'='withdraw' AND (d.kind<>'withdraw' OR (c IS DISTINCT FROM d.control AND NOT EXISTS(SELECT 1 FROM uem_netbird_resolution_retries WHERE family='operation' AND request_id=r.id AND resolution_id=d.id AND kind='withdraw' AND control=c))))
 OR (c->>'kind'='release' AND NOT ((d.kind='release' AND c IS NOT DISTINCT FROM d.control) OR EXISTS(SELECT 1 FROM uem_netbird_resolution_retries WHERE family='operation' AND request_id=r.id AND resolution_id=d.id AND kind='release' AND control=c)))
 OR jsonb_typeof(c->'issued_at') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'expires_at') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'NetBird resolution control is invalid'; END IF;
 IF NOT ((c->>'expires_at')::timestamptz>(c->>'issued_at')::timestamptz AND (c->>'expires_at')::timestamptz<=(c->>'issued_at')::timestamptz+interval '10 seconds') THEN RAISE EXCEPTION 'NetBird resolution deadline is invalid'; END IF;
 state:=jsonb_build_object('status','','revision','','remaining',0,'pending_id','','pending_hash','','can_release',false);
 receipt:=jsonb_build_object('version',1,'request_id',r.id::text,'device_id',r.device_id,'revision',r.revision,'command_hash',d.command_hash,'operation',r.operation,'status',CASE WHEN d.kind='acknowledge' OR (d.kind='withdraw' AND c->>'kind'='receipt' AND p->'receipt'->>'status'='completed') THEN 'completed' WHEN d.kind='withdraw' AND c->>'kind' IN ('receipt','release') AND p->'receipt'->>'status'='unconfirmed' AND EXISTS(SELECT 1 FROM uem_netbird_resolution_retries WHERE family='operation' AND request_id=r.id AND resolution_id=d.id AND kind='release') THEN 'unconfirmed' WHEN d.kind='withdraw' THEN 'withdrawn' ELSE 'unconfirmed' END);
 IF p IS DISTINCT FROM jsonb_build_object('version',CASE WHEN c->'version'='2'::jsonb THEN 2 ELSE 1 END,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',c->'request_id','request_hash',p->'request_hash','kind',c->'kind','outcome','ok','state',state,'receipt',receipt,'release_id',CASE WHEN d.kind='release' OR (d.kind='withdraw' AND receipt->>'status' IN ('withdrawn','unconfirmed')) THEN d.id::text ELSE '' END)
 OR NOT coalesce(p->>'request_hash' ~ '^[0-9a-f]{64}$',false)
 THEN RAISE EXCEPTION 'NetBird resolution response is invalid'; END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION uem_netbird_registration_control_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_registrations%ROWTYPE; d uem_netbird_registration_resolutions%ROWTYPE; c JSONB;
BEGIN
 SELECT * INTO r FROM uem_netbird_registrations WHERE id=NEW.request_id AND status='unconfirmed' AND released_at IS NULL;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM uem_netbird_registration_evidence WHERE request_id=r.id AND kind='absent') THEN RAISE EXCEPTION 'Registration release requires key absence'; END IF;
 SELECT * INTO d FROM uem_netbird_registration_resolutions WHERE request_id=r.id AND id=NEW.resolution_id AND kind<>'not-delivered';
 IF NOT FOUND THEN RAISE EXCEPTION 'Registration resolution intent is missing'; END IF;
 c:=NEW.control;
 IF c IS DISTINCT FROM (jsonb_build_object('version',CASE WHEN d.kind='withdraw' OR (d.kind='acknowledge' AND c->'version'='2'::jsonb) THEN 2 ELSE 1 END,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',c->'request_id','kind',CASE WHEN d.kind='withdraw' THEN c->>'kind' WHEN d.kind='release' THEN 'release' ELSE 'receipt' END,'reference_id',r.id::text,'command_hash',d.command_hash,'issued_at',c->'issued_at','expires_at',c->'expires_at') || CASE WHEN d.kind='withdraw' OR (d.kind='acknowledge' AND c->'version'='2'::jsonb) THEN jsonb_build_object('revision',r.revision,'operation','register') ELSE '{}'::jsonb END)
 OR (d.kind='withdraw' AND NOT coalesce(c->>'kind' IN ('withdraw','receipt'),false))
 OR (c->>'kind'='withdraw' AND c->>'request_id' IS DISTINCT FROM d.id::text)
 OR jsonb_typeof(c->'certificate_hash') IS DISTINCT FROM 'string'
 OR (r.individual AND NOT coalesce(c->>'certificate_hash' ~ '^[0-9a-f]{64}$',false)) OR (NOT r.individual AND c->>'certificate_hash'<>'')
 OR NOT coalesce(c->>'request_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false)
 OR (d.kind='release' AND c->>'request_id' IS DISTINCT FROM d.id::text)
 OR jsonb_typeof(c->'issued_at') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'expires_at') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'Registration resolution control is invalid'; END IF;
 IF NOT ((c->>'expires_at')::timestamptz>(c->>'issued_at')::timestamptz AND (c->>'expires_at')::timestamptz<=(c->>'issued_at')::timestamptz+interval '10 seconds') THEN RAISE EXCEPTION 'Registration control deadline is invalid'; END IF;
 RETURN NEW;
END $$;


CREATE OR REPLACE FUNCTION uem_netbird_registration_proof_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_registrations%ROWTYPE; d uem_netbird_registration_resolutions%ROWTYPE; c JSONB; p JSONB; state JSONB; receipt JSONB;
BEGIN
 SELECT * INTO r FROM uem_netbird_registrations WHERE id=NEW.request_id;
 IF NOT FOUND OR r.status<>'unconfirmed' OR r.released_at IS NOT NULL THEN RAISE EXCEPTION 'NetBird resolution requires an uncertain request'; END IF;
 IF NOT EXISTS(SELECT 1 FROM uem_netbird_registration_evidence WHERE request_id=r.id AND kind='absent') THEN RAISE EXCEPTION 'Registration key absence is missing'; END IF;
 SELECT * INTO d FROM uem_netbird_registration_resolutions WHERE request_id=r.id AND id=NEW.resolution_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'Registration resolution admission is missing'; END IF;
 IF d.kind='not-delivered' THEN
  IF NEW.control<>'{}'::jsonb OR NEW.response<>'{}'::jsonb OR EXISTS(SELECT 1 FROM uem_netbird_registration_attempts WHERE request_id=r.id AND stage='deliver') THEN RAISE EXCEPTION 'Registration delivery was attempted'; END IF;
  RETURN NEW;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM uem_netbird_registration_resolution_attempts WHERE request_id=r.id AND resolution_id=d.id) AND NOT EXISTS(SELECT 1 FROM uem_netbird_resolution_retries WHERE family='registration' AND request_id=r.id AND resolution_id=d.id) THEN RAISE EXCEPTION 'Registration control attempt is missing'; END IF;
 c:=NEW.control; p:=NEW.response;
 IF c IS DISTINCT FROM (jsonb_build_object('version',CASE WHEN c->'version'='2'::jsonb THEN 2 ELSE 1 END,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',c->'request_id','kind',c->'kind','reference_id',r.id::text,'command_hash',d.command_hash,'issued_at',c->'issued_at','expires_at',c->'expires_at') || CASE WHEN c->'version'='2'::jsonb THEN jsonb_build_object('revision',r.revision,'operation','register') ELSE '{}'::jsonb END)
 OR (d.kind='withdraw' AND c->>'kind'<>'release' AND c->'version' IS DISTINCT FROM '2'::jsonb)
 OR (c->>'kind'='release' AND c->'version' IS DISTINCT FROM '1'::jsonb)
 OR jsonb_typeof(c->'certificate_hash') IS DISTINCT FROM 'string'
 OR (r.individual AND NOT coalesce(c->>'certificate_hash' ~ '^[0-9a-f]{64}$',false))
 OR (NOT r.individual AND c->>'certificate_hash'<>'')
 OR NOT coalesce(c->>'request_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false)
 OR NOT coalesce(c->>'kind' IN ('receipt','release','withdraw'),false)
 OR (c->>'kind'='withdraw' AND (d.kind<>'withdraw' OR (c IS DISTINCT FROM (SELECT control FROM uem_netbird_registration_resolution_attempts WHERE request_id=r.id) AND NOT EXISTS(SELECT 1 FROM uem_netbird_resolution_retries WHERE family='registration' AND request_id=r.id AND resolution_id=d.id AND kind='withdraw' AND control=c))))
 OR (c->>'kind'='release' AND NOT ((d.kind='release' AND c IS NOT DISTINCT FROM (SELECT control FROM uem_netbird_registration_resolution_attempts WHERE request_id=r.id)) OR EXISTS(SELECT 1 FROM uem_netbird_resolution_retries WHERE family='registration' AND request_id=r.id AND resolution_id=d.id AND kind='release' AND control=c)))
 OR jsonb_typeof(c->'issued_at') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'expires_at') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'NetBird resolution control is invalid'; END IF;
 IF NOT ((c->>'expires_at')::timestamptz>(c->>'issued_at')::timestamptz AND (c->>'expires_at')::timestamptz<=(c->>'issued_at')::timestamptz+interval '10 seconds') THEN RAISE EXCEPTION 'NetBird resolution deadline is invalid'; END IF;
 state:=jsonb_build_object('status','','revision','','remaining',0,'pending_id','','pending_hash','','can_release',false);
 receipt:=jsonb_build_object('version',1,'request_id',r.id::text,'device_id',r.device_id,'revision',r.revision,'command_hash',d.command_hash,'operation','register','status',CASE WHEN d.kind='acknowledge' OR (d.kind='withdraw' AND c->>'kind'='receipt' AND p->'receipt'->>'status'='completed') THEN 'completed' WHEN d.kind='withdraw' AND c->>'kind' IN ('receipt','release') AND p->'receipt'->>'status'='unconfirmed' AND EXISTS(SELECT 1 FROM uem_netbird_resolution_retries WHERE family='registration' AND request_id=r.id AND resolution_id=d.id AND kind='release') THEN 'unconfirmed' WHEN d.kind='withdraw' THEN 'withdrawn' ELSE 'unconfirmed' END);
 IF p IS DISTINCT FROM jsonb_build_object('version',CASE WHEN c->'version'='2'::jsonb THEN 2 ELSE 1 END,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',c->'request_id','request_hash',p->'request_hash','kind',c->'kind','outcome','ok','state',state,'receipt',receipt,'release_id',CASE WHEN d.kind='release' OR (d.kind='withdraw' AND receipt->>'status' IN ('withdrawn','unconfirmed')) THEN d.id::text ELSE '' END)
 OR NOT coalesce(p->>'request_hash' ~ '^[0-9a-f]{64}$',false)
 THEN RAISE EXCEPTION 'NetBird resolution response is invalid'; END IF;
 RETURN NEW;
END $$;
