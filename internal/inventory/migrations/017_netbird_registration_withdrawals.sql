-- Version-two recovery can durably withdraw a command that has no agent attempt.
-- Existing resolution identity, independent attempt and final proof ordering stay intact.
ALTER TABLE uem_netbird_registration_resolutions DROP CONSTRAINT uem_netbird_registration_resolutions_kind_check;
ALTER TABLE uem_netbird_registration_resolutions ADD CONSTRAINT uem_netbird_registration_resolutions_kind_check CHECK(kind IN ('not-delivered','acknowledge','release','withdraw'));

CREATE OR REPLACE FUNCTION uem_netbird_registration_control_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_registrations%ROWTYPE; d uem_netbird_registration_resolutions%ROWTYPE; c JSONB;
BEGIN
 SELECT * INTO r FROM uem_netbird_registrations WHERE id=NEW.request_id AND status='unconfirmed' AND released_at IS NULL;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM uem_netbird_registration_evidence WHERE request_id=r.id AND kind='absent') THEN RAISE EXCEPTION 'Registration release requires key absence'; END IF;
 SELECT * INTO d FROM uem_netbird_registration_resolutions WHERE request_id=r.id AND id=NEW.resolution_id AND kind<>'not-delivered';
 IF NOT FOUND THEN RAISE EXCEPTION 'Registration resolution intent is missing'; END IF;
 c:=NEW.control;
 IF c IS DISTINCT FROM (jsonb_build_object('version',CASE WHEN d.kind='withdraw' THEN 2 ELSE 1 END,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',c->'request_id','kind',CASE WHEN d.kind='withdraw' THEN c->>'kind' WHEN d.kind='release' THEN 'release' ELSE 'receipt' END,'reference_id',r.id::text,'command_hash',d.command_hash,'issued_at',c->'issued_at','expires_at',c->'expires_at') || CASE WHEN d.kind='withdraw' THEN jsonb_build_object('revision',r.revision,'operation','register') ELSE '{}'::jsonb END)
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
 IF NOT EXISTS(SELECT 1 FROM uem_netbird_registration_resolution_attempts WHERE request_id=r.id AND resolution_id=d.id) THEN RAISE EXCEPTION 'Registration control attempt is missing'; END IF;
 c:=NEW.control; p:=NEW.response;
 IF c IS DISTINCT FROM (jsonb_build_object('version',CASE WHEN d.kind='withdraw' THEN 2 ELSE 1 END,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',c->'request_id','kind',c->'kind','reference_id',r.id::text,'command_hash',d.command_hash,'issued_at',c->'issued_at','expires_at',c->'expires_at') || CASE WHEN d.kind='withdraw' THEN jsonb_build_object('revision',r.revision,'operation','register') ELSE '{}'::jsonb END)
 OR jsonb_typeof(c->'certificate_hash') IS DISTINCT FROM 'string'
 OR (r.individual AND NOT coalesce(c->>'certificate_hash' ~ '^[0-9a-f]{64}$',false))
 OR (NOT r.individual AND c->>'certificate_hash'<>'')
 OR NOT coalesce(c->>'request_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false)
 OR NOT coalesce(c->>'kind' IN ('receipt','release','withdraw'),false)
 OR (c->>'kind'='withdraw' AND (d.kind<>'withdraw' OR c IS DISTINCT FROM (SELECT control FROM uem_netbird_registration_resolution_attempts WHERE request_id=r.id)))
 OR (c->>'kind'='release' AND (d.kind<>'release' OR c IS DISTINCT FROM (SELECT control FROM uem_netbird_registration_resolution_attempts WHERE request_id=r.id)))
 OR jsonb_typeof(c->'issued_at') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'expires_at') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'NetBird resolution control is invalid'; END IF;
 IF NOT ((c->>'expires_at')::timestamptz>(c->>'issued_at')::timestamptz AND (c->>'expires_at')::timestamptz<=(c->>'issued_at')::timestamptz+interval '10 seconds') THEN RAISE EXCEPTION 'NetBird resolution deadline is invalid'; END IF;
 state:=jsonb_build_object('status','','revision','','remaining',0,'pending_id','','pending_hash','','can_release',false);
 receipt:=jsonb_build_object('version',1,'request_id',r.id::text,'device_id',r.device_id,'revision',r.revision,'command_hash',d.command_hash,'operation','register','status',CASE WHEN d.kind='acknowledge' OR (d.kind='withdraw' AND c->>'kind'='receipt' AND p->'receipt'->>'status'='completed') THEN 'completed' WHEN d.kind='withdraw' THEN 'withdrawn' ELSE 'unconfirmed' END);
 IF p IS DISTINCT FROM jsonb_build_object('version',CASE WHEN d.kind='withdraw' THEN 2 ELSE 1 END,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',r.individual,'certificate_hash',c->'certificate_hash','request_id',c->'request_id','request_hash',p->'request_hash','kind',c->'kind','outcome','ok','state',state,'receipt',receipt,'release_id',CASE WHEN d.kind='release' OR (d.kind='withdraw' AND receipt->>'status'='withdrawn') THEN d.id::text ELSE '' END)
 OR NOT coalesce(p->>'request_hash' ~ '^[0-9a-f]{64}$',false)
 THEN RAISE EXCEPTION 'NetBird resolution response is invalid'; END IF;
 RETURN NEW;
END $$;
