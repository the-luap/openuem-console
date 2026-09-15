ALTER TABLE uem_netbird_registrations ADD COLUMN released_at TIMESTAMPTZ, ADD COLUMN released_by TEXT CHECK(length(released_by) BETWEEN 1 AND 255);
ALTER TABLE uem_netbird_registrations ADD CONSTRAINT uem_netbird_registration_release_pair CHECK((released_at IS NULL)=(released_by IS NULL) AND (released_at IS NULL OR status='unconfirmed'));
DROP INDEX uem_netbird_registrations_barrier;
CREATE UNIQUE INDEX uem_netbird_registrations_barrier ON uem_netbird_registrations(device_id) WHERE status='queued' OR (status='unconfirmed' AND released_at IS NULL);

-- Intent, agent attempt and evidence commit separately from the locked original
-- request. No foreign key may block those independent transactions.
CREATE TABLE uem_netbird_registration_resolutions (
 request_id UUID PRIMARY KEY,
 id UUID NOT NULL UNIQUE CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 revision TEXT NOT NULL CHECK(revision ~ '^[0-9a-f]{64}$'),
 kind TEXT NOT NULL CHECK(kind IN ('not-delivered','acknowledge','release')),
 command_hash TEXT NOT NULL CHECK(command_hash='' OR command_hash ~ '^[0-9a-f]{64}$'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK((kind='not-delivered')=(command_hash=''))
);
CREATE TABLE uem_netbird_registration_resolution_attempts (
 request_id UUID PRIMARY KEY,
 resolution_id UUID NOT NULL UNIQUE,
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 control JSONB NOT NULL CHECK(jsonb_typeof(control)='object' AND octet_length(control::text)<=8192),
 control_hash TEXT NOT NULL CHECK(control_hash ~ '^[0-9a-f]{64}$'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE uem_netbird_registration_resolution_evidence (
 request_id UUID PRIMARY KEY,
 resolution_id UUID NOT NULL UNIQUE,
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 control JSONB NOT NULL CHECK(jsonb_typeof(control)='object' AND octet_length(control::text)<=8192),
 response JSONB NOT NULL CHECK(jsonb_typeof(response)='object' AND octet_length(response::text)<=8192),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION uem_netbird_registration_intent_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird registration resolution records are permanent'; END $$;
CREATE TRIGGER uem_netbird_registration_intent_immutable BEFORE UPDATE OR DELETE ON uem_netbird_registration_resolutions FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_intent_immutable();
CREATE FUNCTION uem_netbird_registration_control_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird registration resolution records are permanent'; END $$;
CREATE TRIGGER uem_netbird_registration_control_immutable BEFORE UPDATE OR DELETE ON uem_netbird_registration_resolution_attempts FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_control_immutable();
CREATE FUNCTION uem_netbird_registration_proof_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird registration resolution records are permanent'; END $$;
CREATE TRIGGER uem_netbird_registration_proof_immutable BEFORE UPDATE OR DELETE ON uem_netbird_registration_resolution_evidence FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_proof_immutable();

CREATE FUNCTION uem_netbird_registration_resolution_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_registrations%ROWTYPE; digest TEXT;
BEGIN
 SELECT * INTO r FROM uem_netbird_registrations WHERE id=NEW.request_id AND status='unconfirmed' AND released_at IS NULL;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM uem_netbird_registration_evidence WHERE request_id=r.id AND kind='key') THEN RAISE EXCEPTION 'Registration resolution requires retained key evidence'; END IF;
 SELECT a.digest INTO digest FROM uem_netbird_registration_attempts a WHERE request_id=r.id AND stage='deliver' AND revision=r.revision;
 IF (NEW.kind='not-delivered' AND FOUND) OR (NEW.kind<>'not-delivered' AND (NOT FOUND OR digest IS DISTINCT FROM NEW.command_hash)) THEN RAISE EXCEPTION 'Registration resolution does not match delivery'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_registration_resolution_valid BEFORE INSERT ON uem_netbird_registration_resolutions FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_resolution_valid();

CREATE FUNCTION uem_netbird_registration_control_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_registrations%ROWTYPE; d uem_netbird_registration_resolutions%ROWTYPE; c JSONB;
BEGIN
 SELECT * INTO r FROM uem_netbird_registrations WHERE id=NEW.request_id AND status='unconfirmed' AND released_at IS NULL;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM uem_netbird_registration_evidence WHERE request_id=r.id AND kind='absent') THEN RAISE EXCEPTION 'Registration release requires key absence'; END IF;
 SELECT * INTO d FROM uem_netbird_registration_resolutions WHERE request_id=r.id AND id=NEW.resolution_id AND kind<>'not-delivered';
 IF NOT FOUND THEN RAISE EXCEPTION 'Registration resolution intent is missing'; END IF;
 c:=NEW.control;
 IF c IS DISTINCT FROM jsonb_build_object('version',1,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',c->'request_id','kind',CASE WHEN d.kind='release' THEN 'release' ELSE 'receipt' END,'reference_id',r.id::text,'command_hash',d.command_hash,'issued_at',c->'issued_at','expires_at',c->'expires_at')
 OR jsonb_typeof(c->'certificate_hash') IS DISTINCT FROM 'string'
 OR (r.individual AND NOT coalesce(c->>'certificate_hash' ~ '^[0-9a-f]{64}$',false)) OR (NOT r.individual AND c->>'certificate_hash'<>'')
 OR NOT coalesce(c->>'request_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false)
 OR (d.kind='release' AND c->>'request_id' IS DISTINCT FROM d.id::text)
 OR jsonb_typeof(c->'issued_at') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'expires_at') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'Registration resolution control is invalid'; END IF;
 IF NOT ((c->>'expires_at')::timestamptz>(c->>'issued_at')::timestamptz AND (c->>'expires_at')::timestamptz<=(c->>'issued_at')::timestamptz+interval '10 seconds') THEN RAISE EXCEPTION 'Registration control deadline is invalid'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_registration_control_valid BEFORE INSERT ON uem_netbird_registration_resolution_attempts FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_control_valid();
CREATE FUNCTION uem_netbird_registration_proof_valid() RETURNS trigger LANGUAGE plpgsql AS $$
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
 IF NOT EXISTS(SELECT 1 FROM uem_netbird_registration_resolution_attempts WHERE request_id=r.id AND resolution_id=d.id) THEN RAISE EXCEPTION 'Registration control attempt is missing'; END IF;
 c:=NEW.control; p:=NEW.response;
 IF c IS DISTINCT FROM jsonb_build_object('version',1,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',c->'request_id','kind',c->'kind','reference_id',r.id::text,'command_hash',d.command_hash,'issued_at',c->'issued_at','expires_at',c->'expires_at')
 OR jsonb_typeof(c->'certificate_hash') IS DISTINCT FROM 'string'
 OR (r.individual AND NOT coalesce(c->>'certificate_hash' ~ '^[0-9a-f]{64}$',false))
 OR (NOT r.individual AND c->>'certificate_hash'<>'')
 OR NOT coalesce(c->>'request_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false)
 OR NOT coalesce(c->>'kind' IN ('receipt','release'),false)
 OR (c->>'kind'='release' AND (d.kind<>'release' OR c IS DISTINCT FROM (SELECT control FROM uem_netbird_registration_resolution_attempts WHERE request_id=r.id)))
 OR jsonb_typeof(c->'issued_at') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'expires_at') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'NetBird resolution control is invalid'; END IF;
 IF NOT ((c->>'expires_at')::timestamptz>(c->>'issued_at')::timestamptz AND (c->>'expires_at')::timestamptz<=(c->>'issued_at')::timestamptz+interval '10 seconds') THEN RAISE EXCEPTION 'NetBird resolution deadline is invalid'; END IF;
 state:=jsonb_build_object('status','','revision','','remaining',0,'pending_id','','pending_hash','','can_release',false);
 receipt:=jsonb_build_object('version',1,'request_id',r.id::text,'device_id',r.device_id,'revision',r.revision,'command_hash',d.command_hash,'operation','register','status',CASE WHEN d.kind='acknowledge' THEN 'completed' ELSE 'unconfirmed' END);
 IF p IS DISTINCT FROM jsonb_build_object('version',1,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',c->'request_id','request_hash',p->'request_hash','kind',c->'kind','outcome','ok','state',state,'receipt',receipt,'release_id',CASE WHEN d.kind='release' THEN d.id::text ELSE '' END)
 OR NOT coalesce(p->>'request_hash' ~ '^[0-9a-f]{64}$',false)
 THEN RAISE EXCEPTION 'NetBird resolution response is invalid'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_registration_proof_valid BEFORE INSERT ON uem_netbird_registration_resolution_evidence FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_proof_valid();

CREATE FUNCTION uem_netbird_registration_release_required() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.released_at IS NOT NULL AND (TG_OP='INSERT' OR OLD.released_at IS NULL) THEN
  IF NOT EXISTS(SELECT 1 FROM uem_netbird_registration_resolution_evidence e JOIN uem_netbird_registration_resolutions d ON d.id=e.resolution_id AND d.request_id=e.request_id WHERE e.request_id=NEW.id AND e.actor=NEW.released_by) THEN RAISE EXCEPTION 'Registration release requires provider and agent evidence'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_registration_release_required BEFORE INSERT OR UPDATE ON uem_netbird_registrations FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_release_required();

CREATE OR REPLACE FUNCTION uem_netbird_registration_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE created BOOLEAN; delivered BOOLEAN; cleaned BOOLEAN;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NetBird registration receipts are permanent'; END IF;
 IF (to_jsonb(NEW)-ARRAY['status','reason','finished_at','released_at','released_by']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','reason','finished_at','released_at','released_by']) THEN RAISE EXCEPTION 'NetBird registration identity is immutable'; END IF;
 IF OLD.status<>'queued' AND (to_jsonb(NEW)-ARRAY['released_at','released_by']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['released_at','released_by']) THEN RAISE EXCEPTION 'NetBird registration outcome is immutable'; END IF;
 IF OLD.released_at IS NOT NULL AND (NEW.released_at IS DISTINCT FROM OLD.released_at OR NEW.released_by IS DISTINCT FROM OLD.released_by) THEN RAISE EXCEPTION 'Registration release is immutable'; END IF;
 IF NEW.status<>OLD.status THEN
  SELECT EXISTS(SELECT 1 FROM uem_netbird_registration_attempts WHERE request_id=NEW.id AND stage='create'),
   EXISTS(SELECT 1 FROM uem_netbird_registration_attempts WHERE request_id=NEW.id AND stage='deliver'),
   EXISTS(SELECT 1 FROM uem_netbird_registration_evidence WHERE request_id=NEW.id AND kind='absent') INTO created,delivered,cleaned;
  IF (NEW.status='completed' AND (NOT cleaned OR NOT EXISTS(SELECT 1 FROM uem_netbird_registration_evidence WHERE request_id=NEW.id AND kind='delivered')))
   OR (NEW.status='stopped' AND (delivered OR (created AND NOT cleaned)))
   OR (NEW.status='unconfirmed' AND NOT created) THEN RAISE EXCEPTION 'NetBird registration outcome lacks evidence'; END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION uem_netbird_registration_attempt_valid() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM uem_netbird_registrations WHERE id=NEW.request_id AND revision=NEW.revision AND (status='queued' OR (NEW.stage='delete' AND status='unconfirmed' AND released_at IS NULL AND EXISTS(SELECT 1 FROM uem_netbird_registration_resolutions WHERE request_id=NEW.request_id)))) THEN RAISE EXCEPTION 'NetBird registration request is missing'; END IF;
 IF NEW.stage<>'create' AND NOT EXISTS(SELECT 1 FROM uem_netbird_registration_evidence WHERE request_id=NEW.request_id AND kind='key') THEN RAISE EXCEPTION 'NetBird registration key evidence is missing'; END IF;
 IF NEW.stage='deliver' AND EXISTS(SELECT 1 FROM uem_netbird_registration_attempts WHERE request_id=NEW.request_id AND stage='delete') THEN RAISE EXCEPTION 'NetBird registration key is being removed'; END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION uem_netbird_registration_admission() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(684629916,hashtext(NEW.id::text));
 PERFORM pg_advisory_xact_lock(684629914,hashtext(NEW.device_id));
 IF (TG_TABLE_NAME='uem_netbird_registrations' AND EXISTS(SELECT 1 FROM uem_netbird_operations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))))
  OR (TG_TABLE_NAME='uem_netbird_operations' AND EXISTS(SELECT 1 FROM uem_netbird_registrations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL))))) THEN RAISE EXCEPTION 'NetBird request conflicts with a recorded registration'; END IF;
 RETURN NEW;
END $$;
