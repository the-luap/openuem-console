ALTER TABLE uem_netbird_installations ADD COLUMN completed_at TIMESTAMPTZ;
ALTER TABLE uem_netbird_installations ADD CONSTRAINT uem_netbird_installation_completion_time
 CHECK(completed_at IS NULL OR (cancelled_at IS NULL AND completed_at>=requested_at));
DROP INDEX uem_netbird_installations_barrier;
CREATE UNIQUE INDEX uem_netbird_installations_barrier ON uem_netbird_installations(device_id)
 WHERE cancelled_at IS NULL AND completed_at IS NULL;

CREATE TABLE uem_netbird_installation_attempts (
 request_id UUID PRIMARY KEY REFERENCES uem_netbird_preparations(request_id),
 wire_version INTEGER NOT NULL CHECK(wire_version=3),
 certificate_hash TEXT NOT NULL CHECK(certificate_hash ~ '^[0-9a-f]{64}$'),
 command_hash TEXT NOT NULL CHECK(command_hash ~ '^[0-9a-f]{64}$'),
 issued_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '10 minutes')
);
CREATE TABLE uem_netbird_installation_results (
 request_id UUID PRIMARY KEY REFERENCES uem_netbird_installation_attempts(request_id),
 outcome TEXT NOT NULL CHECK(outcome IN ('completed','unconfirmed')),
 receipt JSONB,
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE uem_netbird_installation_observations (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 request_id UUID NOT NULL REFERENCES uem_netbird_installation_attempts(request_id),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 control_hash TEXT NOT NULL CHECK(control_hash ~ '^[0-9a-f]{64}$'),
 control JSONB NOT NULL CHECK(octet_length(control::text)<=16384),
 response JSONB CHECK(octet_length(response::text)<=16384),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX uem_netbird_installation_observations_history ON uem_netbird_installation_observations(request_id,recorded_at DESC,id DESC);
CREATE FUNCTION uem_netbird_installation_attempt_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird installation attempts are permanent'; END $$;
CREATE TRIGGER uem_netbird_installation_attempt_immutable BEFORE UPDATE OR DELETE ON uem_netbird_installation_attempts
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_installation_attempt_immutable();
CREATE FUNCTION uem_netbird_installation_result_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird installation results are permanent'; END $$;
CREATE TRIGGER uem_netbird_installation_result_immutable BEFORE UPDATE OR DELETE ON uem_netbird_installation_results
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_installation_result_immutable();
CREATE FUNCTION uem_netbird_installation_observation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird installation observations are permanent'; END $$;
CREATE TRIGGER uem_netbird_installation_observation_immutable BEFORE UPDATE OR DELETE ON uem_netbird_installation_observations
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_installation_observation_immutable();

CREATE FUNCTION uem_netbird_installation_attempt_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_installations%ROWTYPE; p uem_netbird_preparations%ROWTYPE; prepared_at TIMESTAMPTZ; valid BOOLEAN;
BEGIN
 SELECT * INTO r FROM uem_netbird_installations WHERE id=NEW.request_id FOR UPDATE;
 IF NOT FOUND OR r.cancelled_at IS NOT NULL OR r.completed_at IS NOT NULL OR clock_timestamp()>=r.expires_at
 THEN RAISE EXCEPTION 'NetBird installation request is unavailable'; END IF;
 SELECT * INTO p FROM uem_netbird_preparations WHERE request_id=r.id;
 SELECT recorded_at INTO prepared_at FROM uem_netbird_preparation_results WHERE request_id=r.id AND outcome='prepared';
 IF NOT FOUND OR p.certificate_hash<>NEW.certificate_hash OR clock_timestamp()>=p.expires_at
  OR NEW.issued_at<p.issued_at OR NEW.issued_at<prepared_at OR NEW.issued_at>clock_timestamp()+interval '5 seconds'
  OR NEW.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'NetBird installation preparation is unavailable'; END IF;
 PERFORM 1 FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id
  WHERE i.id=r.device_id::uuid FOR SHARE OF i,q;
 SELECT EXISTS(SELECT 1 FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id
  WHERE i.id=r.device_id::uuid AND i.tenant_id=r.tenant_id AND i.site_id=r.site_id
   AND i.certificate_hash=NEW.certificate_hash AND i.certificate_expires_at>=NEW.expires_at
   AND i.revoked_at IS NULL AND q.desired_active AND q.revision=q.completed_revision) INTO valid;
 IF NOT valid THEN RAISE EXCEPTION 'NetBird installation recipient changed'; END IF;
 PERFORM 1 FROM uem_netbird_packages WHERE id=r.approval_id FOR SHARE;
 SELECT EXISTS(SELECT 1 FROM uem_netbird_packages pkg WHERE pkg.id=r.approval_id AND pkg.tenant_id=r.tenant_id AND pkg.digest=r.approval_digest
  AND NOT EXISTS(SELECT 1 FROM uem_netbird_package_revocations v WHERE v.approval_id=pkg.id)) INTO valid;
 IF NOT valid THEN RAISE EXCEPTION 'NetBird installation approval changed'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_installation_attempt_valid BEFORE INSERT ON uem_netbird_installation_attempts
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_installation_attempt_valid();

CREATE FUNCTION uem_netbird_installation_result_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_installations%ROWTYPE; a uem_netbird_installation_attempts%ROWTYPE; status TEXT;
BEGIN
 SELECT * INTO r FROM uem_netbird_installations WHERE id=NEW.request_id FOR UPDATE;
 SELECT * INTO a FROM uem_netbird_installation_attempts WHERE request_id=NEW.request_id;
 IF NOT FOUND OR NEW.recorded_at<a.issued_at OR NEW.recorded_at>clock_timestamp()+interval '5 seconds'
 THEN RAISE EXCEPTION 'NetBird installation result has no matching attempt'; END IF;
 IF NEW.receipt IS NOT NULL THEN
  status=NEW.receipt->>'status';
  IF NOT coalesce(status IN ('completed','unconfirmed','busy','rejected','withdrawn'),false)
   OR NEW.receipt IS DISTINCT FROM jsonb_build_object('version',1,'request_id',r.id::text,'device_id',r.device_id,
    'revision',r.revision,'command_hash',a.command_hash,'operation','install','status',status)
  THEN RAISE EXCEPTION 'NetBird installation receipt does not match'; END IF;
 END IF;
 IF (NEW.outcome='completed') IS DISTINCT FROM coalesce(status='completed',false)
 THEN RAISE EXCEPTION 'NetBird installation outcome has no matching receipt'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_installation_result_valid BEFORE INSERT ON uem_netbird_installation_results
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_installation_result_valid();

CREATE FUNCTION uem_netbird_installation_observation_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_installations%ROWTYPE; a uem_netbird_installation_attempts%ROWTYPE; c JSONB; p JSONB; empty_state JSONB; receipt JSONB; status TEXT;
BEGIN
 SELECT * INTO r FROM uem_netbird_installations WHERE id=NEW.request_id FOR UPDATE;
 SELECT * INTO a FROM uem_netbird_installation_attempts WHERE request_id=NEW.request_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'NetBird installation observation has no attempt'; END IF;
 c=NEW.control; p=NEW.response;
 IF c IS DISTINCT FROM jsonb_build_object('version',2,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,
   'individual',true,'certificate_hash',c->'certificate_hash','request_id',NEW.id::text,'kind','receipt','reference_id',r.id::text,
   'command_hash',a.command_hash,'issued_at',c->'issued_at','expires_at',c->'expires_at','revision',r.revision,'operation','install')
  OR jsonb_typeof(c->'certificate_hash') IS DISTINCT FROM 'string' OR NOT coalesce(c->>'certificate_hash' ~ '^[0-9a-f]{64}$',false)
  OR jsonb_typeof(c->'issued_at') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'expires_at') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'NetBird installation observation control is invalid'; END IF;
 IF NOT ((c->>'expires_at')::timestamptz>(c->>'issued_at')::timestamptz AND (c->>'expires_at')::timestamptz<=(c->>'issued_at')::timestamptz+interval '10 seconds')
  OR NEW.recorded_at<(c->>'issued_at')::timestamptz OR NEW.recorded_at>clock_timestamp()+interval '5 seconds'
 THEN RAISE EXCEPTION 'NetBird installation observation time is invalid'; END IF;
 IF p IS NULL THEN RETURN NEW; END IF;
 empty_state=jsonb_build_object('status','','revision','','remaining',0,'pending_id','','pending_hash','','can_release',false);
 IF p->>'outcome'='ok' THEN
  status=p->'receipt'->>'status';
  IF NOT coalesce(status IN ('completed','unconfirmed','withdrawn'),false) THEN RAISE EXCEPTION 'NetBird installation observation receipt is invalid'; END IF;
  receipt=jsonb_build_object('version',1,'request_id',r.id::text,'device_id',r.device_id,'revision',r.revision,'command_hash',a.command_hash,'operation','install','status',status);
  IF (status='completed' AND p->>'release_id'<>'') OR (status='withdrawn' AND p->>'release_id'='')
   OR (p->>'release_id'<>'' AND NOT coalesce(p->>'release_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false))
   OR p->>'release_id'='00000000-0000-0000-0000-000000000000'
  THEN RAISE EXCEPTION 'NetBird installation release evidence is invalid'; END IF;
 ELSE
  IF NOT coalesce(p->>'outcome' IN ('missing','blocked','conflict','unavailable'),false) OR p->>'release_id'<>''
  THEN RAISE EXCEPTION 'NetBird installation observation outcome is invalid'; END IF;
  receipt=jsonb_build_object('version',0,'request_id','','device_id','','revision','','command_hash','','operation','','status','');
 END IF;
 IF p IS DISTINCT FROM jsonb_build_object('version',2,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,
   'individual',true,'certificate_hash',c->'certificate_hash','request_id',NEW.id::text,'request_hash',NEW.control_hash,'kind','receipt',
   'outcome',p->'outcome','state',empty_state,'receipt',receipt,'release_id',p->'release_id')
  OR jsonb_typeof(p->'release_id') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'NetBird installation observation response does not match'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_installation_observation_valid BEFORE INSERT ON uem_netbird_installation_observations
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_installation_observation_valid();

CREATE OR REPLACE FUNCTION uem_netbird_installation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NetBird installation requests are permanent'; END IF;
 IF (to_jsonb(NEW)-ARRAY['cancellation_id','cancelled_by','cancelled_at','completed_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['cancellation_id','cancelled_by','cancelled_at','completed_at'])
  OR ((OLD.cancelled_at IS NOT NULL OR OLD.completed_at IS NOT NULL) AND NEW IS DISTINCT FROM OLD)
 THEN RAISE EXCEPTION 'NetBird installation intent and completion are immutable'; END IF;
 IF NEW.cancelled_at IS NOT NULL AND OLD.cancelled_at IS NULL
  AND EXISTS(SELECT 1 FROM uem_netbird_installation_attempts WHERE request_id=NEW.id)
 THEN RAISE EXCEPTION 'NetBird installation delivery cannot be cancelled'; END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION uem_netbird_installation_completion_valid() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' AND NEW.completed_at IS NOT NULL THEN RAISE EXCEPTION 'NetBird installation cannot begin completed'; END IF;
 IF TG_OP='UPDATE' AND OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL THEN
  IF NOT EXISTS(SELECT 1 FROM uem_netbird_installation_results WHERE request_id=NEW.id AND outcome='completed' AND recorded_at=NEW.completed_at)
   AND NOT EXISTS(SELECT 1 FROM uem_netbird_installation_observations WHERE request_id=NEW.id AND recorded_at=NEW.completed_at
    AND response->>'outcome'='ok' AND response->'receipt'->>'status'='completed' AND response->>'release_id'='')
  THEN RAISE EXCEPTION 'NetBird installation completion requires retained evidence'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_installation_completion_valid BEFORE INSERT OR UPDATE ON uem_netbird_installations
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_installation_completion_valid();

CREATE OR REPLACE FUNCTION uem_netbird_registration_admission() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(684629916,hashtext(NEW.id::text));
 PERFORM pg_advisory_xact_lock(684629914,hashtext(NEW.device_id));
 IF (TG_TABLE_NAME<>'uem_netbird_operations' AND EXISTS(SELECT 1 FROM uem_netbird_operations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))))
  OR (TG_TABLE_NAME<>'uem_netbird_registrations' AND EXISTS(SELECT 1 FROM uem_netbird_registrations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))))
  OR (TG_TABLE_NAME<>'uem_netbird_installations' AND EXISTS(SELECT 1 FROM uem_netbird_installations WHERE id=NEW.id OR (device_id=NEW.device_id AND cancelled_at IS NULL AND completed_at IS NULL)))
 THEN RAISE EXCEPTION 'NetBird request conflicts with a retained operation'; END IF;
 RETURN NEW;
END $$;
