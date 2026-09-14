-- Independent explicitly reviewed scaffold cleanup, not original removal success.
-- The original uninstall and its owned release evidence remain immutable.
-- Independent attempts, receipts and reviewed resolutions belong to the new cleanup.
CREATE TABLE uem_netbird_removal_stage_cleanups (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 original_id UUID NOT NULL REFERENCES uem_netbird_removal_release_proofs(request_id) CHECK(original_id<>id),
 device_id TEXT NOT NULL CHECK(device_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND device_id<>'00000000-0000-0000-0000-000000000000'),
 tenant_id BIGINT NOT NULL CHECK(tenant_id>0),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 revision TEXT NOT NULL CHECK(revision ~ '^[0-9a-f]{64}$'),
 journal_revision TEXT NOT NULL CHECK(journal_revision ~ '^[0-9a-f]{64}$'),
 stage_cleanup_digest TEXT NOT NULL CHECK(stage_cleanup_digest ~ '^[0-9a-f]{64}$'),
 stage_cleanup JSONB NOT NULL CHECK(octet_length(stage_cleanup::text)<=8192),
 requested_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 cancellation_id UUID UNIQUE CHECK(cancellation_id<>'00000000-0000-0000-0000-000000000000'::uuid AND cancellation_id<>id AND cancellation_id<>original_id),
 cancelled_by TEXT CHECK(octet_length(cancelled_by) BETWEEN 1 AND 255),
 cancelled_at TIMESTAMPTZ,
 CHECK(expires_at>requested_at AND expires_at<=requested_at+interval '2 minutes'),
 CHECK((cancellation_id IS NULL)=(cancelled_by IS NULL) AND (cancellation_id IS NULL)=(cancelled_at IS NULL)),
 CHECK(cancelled_at IS NULL OR cancelled_at>=requested_at),
 CHECK(cancellation_id IS NULL OR cancellation_id::text IS DISTINCT FROM stage_cleanup->'original'->>'release_id')
);
CREATE UNIQUE INDEX uem_netbird_removal_stage_cleanups_barrier ON uem_netbird_removal_stage_cleanups(device_id) WHERE cancelled_at IS NULL;
CREATE INDEX uem_netbird_removal_stage_cleanups_history ON uem_netbird_removal_stage_cleanups(tenant_id,site_id,device_id,requested_at DESC,id DESC);

CREATE FUNCTION uem_netbird_removal_stage_cleanup_initial() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_removals%ROWTYPE; a uem_netbird_removal_attempts%ROWTYPE;
 proof uem_netbird_removal_release_proofs%ROWTYPE; response JSONB; observed TIMESTAMPTZ; original JSONB;
BEGIN
 PERFORM pg_advisory_xact_lock(684629916,hashtext(NEW.id::text));
 PERFORM pg_advisory_xact_lock(684629914,hashtext(NEW.device_id));
 IF NEW.cancelled_at IS NOT NULL THEN RAISE EXCEPTION 'NetBird stage cleanup cannot begin cancelled'; END IF;
 SELECT * INTO r FROM uem_netbird_removals WHERE id=NEW.original_id FOR SHARE;
 IF NOT FOUND OR r.device_id<>NEW.device_id OR r.tenant_id<>NEW.tenant_id OR r.site_id<>NEW.site_id
  OR r.cancelled_at IS NOT NULL OR r.completed_at IS NOT NULL OR r.released_at IS NULL
  OR r.resolution_id IS NULL OR NEW.id=r.resolution_id OR r.descriptor->>'platform' IS DISTINCT FROM 'macos'
 THEN RAISE EXCEPTION 'NetBird stage cleanup requires the exact released original removal'; END IF;
 SELECT * INTO a FROM uem_netbird_removal_attempts WHERE request_id=r.id;
 IF NOT FOUND THEN RAISE EXCEPTION 'NetBird stage cleanup requires an original native attempt'; END IF;
 SELECT * INTO proof FROM uem_netbird_removal_release_proofs WHERE request_id=r.id AND resolution_id=r.resolution_id;
 IF NOT FOUND OR proof.actor<>r.released_by OR proof.recorded_at<>r.released_at OR proof.recorded_at>NEW.requested_at
 THEN RAISE EXCEPTION 'NetBird stage cleanup requires owned original release proof'; END IF;
 IF proof.attempt_id IS NOT NULL THEN
  SELECT v.response,v.recorded_at INTO response,observed FROM uem_netbird_removal_control_results v
   JOIN uem_netbird_removal_controls c ON c.id=v.attempt_id
   WHERE c.id=proof.attempt_id AND c.request_id=r.id AND c.resolution_id=r.resolution_id AND c.kind='release';
 ELSE
  SELECT o.response,o.recorded_at INTO response,observed FROM uem_netbird_removal_observations o
   WHERE o.id=proof.observation_id AND o.request_id=r.id;
 END IF;
 IF response->>'outcome' IS DISTINCT FROM 'ok' OR response->>'release_id' IS DISTINCT FROM r.resolution_id::text
  OR response->'receipt' IS DISTINCT FROM jsonb_build_object('version',1,'request_id',r.id::text,'device_id',r.device_id,
   'revision',r.revision,'command_hash',a.command_hash,'operation','uninstall','status','unconfirmed')
  OR observed IS NULL OR observed>proof.recorded_at
  OR NOT EXISTS(SELECT 1 FROM uem_netbird_removal_controls c WHERE c.request_id=r.id AND c.resolution_id=r.resolution_id AND c.kind='release' AND c.created_at<=observed)
 THEN RAISE EXCEPTION 'NetBird stage cleanup cannot use withdrawn or foreign removal evidence'; END IF;
 original=jsonb_build_object('request_id',r.id::text,'command_hash',a.command_hash,'revision',r.revision,'release_id',r.resolution_id::text);
 IF NEW.stage_cleanup IS DISTINCT FROM jsonb_build_object('original',original,'profile','macos-official-pkg-stage-v1','journal_revision',NEW.journal_revision,'state_digest',NEW.stage_cleanup->'state_digest','directory_count',NEW.stage_cleanup->'directory_count','manifest_present',NEW.stage_cleanup->'manifest_present','manifest_bytes',NEW.stage_cleanup->'manifest_bytes')
  OR jsonb_typeof(NEW.stage_cleanup->'state_digest') IS DISTINCT FROM 'string'
  OR NOT coalesce(NEW.stage_cleanup->>'state_digest' ~ '^[0-9a-f]{64}$',false)
  OR jsonb_typeof(NEW.stage_cleanup->'directory_count') IS DISTINCT FROM 'number'
  OR NOT coalesce(NEW.stage_cleanup->>'directory_count' ~ '^[0-9]+$',false)
  OR (NEW.stage_cleanup->>'directory_count')::integer NOT BETWEEN 1 AND 7
  OR jsonb_typeof(NEW.stage_cleanup->'manifest_present') IS DISTINCT FROM 'boolean'
  OR jsonb_typeof(NEW.stage_cleanup->'manifest_bytes') IS DISTINCT FROM 'number'
  OR NOT coalesce(NEW.stage_cleanup->>'manifest_bytes' ~ '^[0-9]+$',false)
  OR (NEW.stage_cleanup->>'manifest_bytes')::bigint NOT BETWEEN 0 AND 2097152
  OR (NEW.stage_cleanup->>'manifest_present'='false' AND NEW.stage_cleanup->>'manifest_bytes'<>'0')
 THEN RAISE EXCEPTION 'NetBird stage cleanup descriptor does not match original evidence'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_initial BEFORE INSERT ON uem_netbird_removal_stage_cleanups
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_initial();

CREATE FUNCTION uem_netbird_removal_stage_cleanup_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NetBird stage cleanup requests are permanent'; END IF;
 IF (to_jsonb(NEW)-ARRAY['cancellation_id','cancelled_by','cancelled_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['cancellation_id','cancelled_by','cancelled_at'])
  OR (OLD.cancelled_at IS NOT NULL AND NEW IS DISTINCT FROM OLD)
 THEN RAISE EXCEPTION 'NetBird stage cleanup intent and cancellation are immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_stage_cleanups
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_immutable();

-- Extend the existing permanent request UUID and unresolved-device namespace.
CREATE TRIGGER uem_netbird_registration_admission BEFORE INSERT ON uem_netbird_removal_stage_cleanups
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_admission();

ALTER TABLE uem_netbird_removal_stage_cleanups ADD COLUMN completed_at TIMESTAMPTZ;
ALTER TABLE uem_netbird_removal_stage_cleanups ADD CONSTRAINT uem_netbird_removal_stage_cleanup_completion_time
 CHECK(completed_at IS NULL OR (cancelled_at IS NULL AND completed_at>=requested_at));
DROP INDEX uem_netbird_removal_stage_cleanups_barrier;
CREATE UNIQUE INDEX uem_netbird_removal_stage_cleanups_barrier ON uem_netbird_removal_stage_cleanups(device_id)
 WHERE cancelled_at IS NULL AND completed_at IS NULL;

CREATE TABLE uem_netbird_removal_stage_cleanup_attempts (
 request_id UUID PRIMARY KEY REFERENCES uem_netbird_removal_stage_cleanups(id),
 wire_version INTEGER NOT NULL CHECK(wire_version=7),
 certificate_hash TEXT NOT NULL CHECK(certificate_hash ~ '^[0-9a-f]{64}$'),
 command_hash TEXT NOT NULL CHECK(command_hash ~ '^[0-9a-f]{64}$'),
 issued_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes')
);
CREATE TABLE uem_netbird_removal_stage_cleanup_results (
 request_id UUID PRIMARY KEY REFERENCES uem_netbird_removal_stage_cleanup_attempts(request_id),
 outcome TEXT NOT NULL CHECK(outcome IN ('completed','unconfirmed')),
 receipt JSONB,
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE uem_netbird_removal_stage_cleanup_observations (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 request_id UUID NOT NULL REFERENCES uem_netbird_removal_stage_cleanup_attempts(request_id),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 control_hash TEXT NOT NULL CHECK(control_hash ~ '^[0-9a-f]{64}$'),
 control JSONB NOT NULL CHECK(octet_length(control::text)<=16384),
 response JSONB CHECK(octet_length(response::text)<=16384),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX uem_netbird_removal_stage_cleanup_observations_history ON uem_netbird_removal_stage_cleanup_observations(request_id,recorded_at DESC,id DESC);
CREATE FUNCTION uem_netbird_removal_stage_cleanup_attempt_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird stage cleanup attempts are permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_attempt_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_stage_cleanup_attempts
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_attempt_immutable();
CREATE FUNCTION uem_netbird_removal_stage_cleanup_result_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird stage cleanup results are permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_result_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_stage_cleanup_results
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_result_immutable();
CREATE FUNCTION uem_netbird_removal_stage_cleanup_observation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird stage cleanup observations are permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_observation_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_stage_cleanup_observations
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_observation_immutable();

CREATE FUNCTION uem_netbird_removal_stage_cleanup_attempt_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_removal_stage_cleanups%ROWTYPE; valid BOOLEAN;
BEGIN
 SELECT * INTO r FROM uem_netbird_removal_stage_cleanups WHERE id=NEW.request_id FOR UPDATE;
 IF NOT FOUND OR r.cancelled_at IS NOT NULL OR r.completed_at IS NOT NULL OR clock_timestamp()>=r.expires_at
 THEN RAISE EXCEPTION 'NetBird stage cleanup request is unavailable'; END IF;
 IF NEW.issued_at<r.requested_at OR NEW.issued_at>clock_timestamp()+interval '5 seconds'
  OR NEW.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'NetBird stage cleanup attempt requires fresh command times'; END IF;
 PERFORM 1 FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id
  WHERE i.id=r.device_id::uuid FOR SHARE OF i,q;
 SELECT EXISTS(SELECT 1 FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id
  WHERE i.id=r.device_id::uuid AND i.tenant_id=r.tenant_id AND i.site_id=r.site_id
   AND i.certificate_hash=NEW.certificate_hash AND i.certificate_expires_at>=NEW.expires_at
   AND i.revoked_at IS NULL AND q.desired_active AND q.revision=q.completed_revision) INTO valid;
 IF NOT valid THEN RAISE EXCEPTION 'NetBird stage cleanup recipient changed'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_attempt_valid BEFORE INSERT ON uem_netbird_removal_stage_cleanup_attempts
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_attempt_valid();

CREATE FUNCTION uem_netbird_removal_stage_cleanup_result_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_removal_stage_cleanups%ROWTYPE; a uem_netbird_removal_stage_cleanup_attempts%ROWTYPE; status TEXT;
BEGIN
 SELECT * INTO r FROM uem_netbird_removal_stage_cleanups WHERE id=NEW.request_id FOR UPDATE;
 SELECT * INTO a FROM uem_netbird_removal_stage_cleanup_attempts WHERE request_id=NEW.request_id;
 IF NOT FOUND OR NEW.recorded_at<a.issued_at OR NEW.recorded_at>clock_timestamp()+interval '5 seconds'
 THEN RAISE EXCEPTION 'NetBird stage cleanup result has no matching attempt'; END IF;
 IF NEW.receipt IS NOT NULL THEN
  status=NEW.receipt->>'status';
  IF NOT coalesce(status IN ('completed','unconfirmed','busy','rejected','withdrawn'),false)
   OR NEW.receipt IS DISTINCT FROM jsonb_build_object('version',1,'request_id',r.id::text,'device_id',r.device_id,
    'revision',r.revision,'command_hash',a.command_hash,'operation','cleanup-removal-stage','status',status)
  THEN RAISE EXCEPTION 'NetBird stage cleanup receipt does not match'; END IF;
 END IF;
 IF (NEW.outcome='completed') IS DISTINCT FROM coalesce(status='completed',false)
 THEN RAISE EXCEPTION 'NetBird stage cleanup outcome has no matching receipt'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_result_valid BEFORE INSERT ON uem_netbird_removal_stage_cleanup_results
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_result_valid();

CREATE FUNCTION uem_netbird_removal_stage_cleanup_observation_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_removal_stage_cleanups%ROWTYPE; a uem_netbird_removal_stage_cleanup_attempts%ROWTYPE; c JSONB; p JSONB; empty_state JSONB; receipt JSONB; status TEXT;
BEGIN
 SELECT * INTO r FROM uem_netbird_removal_stage_cleanups WHERE id=NEW.request_id FOR UPDATE;
 SELECT * INTO a FROM uem_netbird_removal_stage_cleanup_attempts WHERE request_id=NEW.request_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'NetBird stage cleanup observation has no attempt'; END IF;
 c=NEW.control; p=NEW.response;
 IF c IS DISTINCT FROM jsonb_build_object('version',2,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,
   'individual',true,'certificate_hash',c->'certificate_hash','request_id',NEW.id::text,'kind','receipt','reference_id',r.id::text,
   'command_hash',a.command_hash,'issued_at',c->'issued_at','expires_at',c->'expires_at','revision',r.revision,'operation','cleanup-removal-stage')
  OR jsonb_typeof(c->'certificate_hash') IS DISTINCT FROM 'string' OR NOT coalesce(c->>'certificate_hash' ~ '^[0-9a-f]{64}$',false)
  OR jsonb_typeof(c->'issued_at') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'expires_at') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'NetBird stage cleanup observation control is invalid'; END IF;
 IF NOT ((c->>'expires_at')::timestamptz>(c->>'issued_at')::timestamptz AND (c->>'expires_at')::timestamptz<=(c->>'issued_at')::timestamptz+interval '10 seconds')
  OR NEW.recorded_at<(c->>'issued_at')::timestamptz OR NEW.recorded_at>clock_timestamp()+interval '5 seconds'
 THEN RAISE EXCEPTION 'NetBird stage cleanup observation time is invalid'; END IF;
 IF p IS NULL THEN RETURN NEW; END IF;
 empty_state=jsonb_build_object('status','','revision','','remaining',0,'pending_id','','pending_hash','','can_release',false);
 IF p->>'outcome'='ok' THEN
  status=p->'receipt'->>'status';
  IF NOT coalesce(status IN ('completed','unconfirmed','withdrawn'),false) THEN RAISE EXCEPTION 'NetBird stage cleanup observation receipt is invalid'; END IF;
  receipt=jsonb_build_object('version',1,'request_id',r.id::text,'device_id',r.device_id,'revision',r.revision,'command_hash',a.command_hash,'operation','cleanup-removal-stage','status',status);
  IF (status='completed' AND p->>'release_id'<>'') OR (status='withdrawn' AND p->>'release_id'='')
   OR (p->>'release_id'<>'' AND NOT coalesce(p->>'release_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false))
   OR p->>'release_id'='00000000-0000-0000-0000-000000000000'
  THEN RAISE EXCEPTION 'NetBird stage cleanup release evidence is invalid'; END IF;
 ELSE
  IF NOT coalesce(p->>'outcome' IN ('missing','blocked','conflict','unavailable'),false) OR p->>'release_id'<>''
  THEN RAISE EXCEPTION 'NetBird stage cleanup observation outcome is invalid'; END IF;
  receipt=jsonb_build_object('version',0,'request_id','','device_id','','revision','','command_hash','','operation','','status','');
 END IF;
 IF p IS DISTINCT FROM jsonb_build_object('version',2,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,
   'individual',true,'certificate_hash',c->'certificate_hash','request_id',NEW.id::text,'request_hash',NEW.control_hash,'kind','receipt',
   'outcome',p->'outcome','state',empty_state,'receipt',receipt,'release_id',p->'release_id')
  OR jsonb_typeof(p->'release_id') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'NetBird stage cleanup observation response does not match'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_observation_valid BEFORE INSERT ON uem_netbird_removal_stage_cleanup_observations
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_observation_valid();

CREATE OR REPLACE FUNCTION uem_netbird_removal_stage_cleanup_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NetBird stage cleanup requests are permanent'; END IF;
 IF (to_jsonb(NEW)-ARRAY['cancellation_id','cancelled_by','cancelled_at','completed_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['cancellation_id','cancelled_by','cancelled_at','completed_at'])
  OR ((OLD.cancelled_at IS NOT NULL OR OLD.completed_at IS NOT NULL) AND NEW IS DISTINCT FROM OLD)
 THEN RAISE EXCEPTION 'NetBird stage cleanup intent and completion are immutable'; END IF;
 IF NEW.cancelled_at IS NOT NULL AND OLD.cancelled_at IS NULL
  AND EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanup_attempts WHERE request_id=NEW.id)
 THEN RAISE EXCEPTION 'NetBird stage cleanup delivery cannot be cancelled'; END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION uem_netbird_removal_stage_cleanup_completion_valid() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' AND NEW.completed_at IS NOT NULL THEN RAISE EXCEPTION 'NetBird stage cleanup cannot begin completed'; END IF;
 IF TG_OP='UPDATE' AND OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL THEN
  IF NOT EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanup_results WHERE request_id=NEW.id AND outcome='completed' AND recorded_at=NEW.completed_at)
   AND NOT EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanup_observations WHERE request_id=NEW.id AND recorded_at=NEW.completed_at
    AND response->>'outcome'='ok' AND response->'receipt'->>'status'='completed' AND response->>'release_id'='')
  THEN RAISE EXCEPTION 'NetBird stage cleanup completion requires retained evidence'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_completion_valid BEFORE INSERT OR UPDATE ON uem_netbird_removal_stage_cleanups
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_completion_valid();



-- A released uncertain cleanup remains distinct from a completed cleanup.
ALTER TABLE uem_netbird_removal_stage_cleanups ADD COLUMN released_at TIMESTAMPTZ,
 ADD COLUMN released_by TEXT, ADD COLUMN resolution_id UUID;
ALTER TABLE uem_netbird_removal_stage_cleanups ADD CONSTRAINT uem_netbird_removal_stage_cleanup_release_metadata CHECK(
 (released_at IS NULL AND released_by IS NULL AND resolution_id IS NULL) OR
 (released_at IS NOT NULL AND released_by IS NOT NULL AND resolution_id IS NOT NULL
  AND octet_length(released_by) BETWEEN 1 AND 255 AND released_at>=requested_at
  AND completed_at IS NULL AND cancelled_at IS NULL));
DROP INDEX uem_netbird_removal_stage_cleanups_barrier;
CREATE UNIQUE INDEX uem_netbird_removal_stage_cleanups_barrier ON uem_netbird_removal_stage_cleanups(device_id)
 WHERE cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL;

CREATE TABLE uem_netbird_removal_stage_cleanup_reviews (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 request_id UUID NOT NULL REFERENCES uem_netbird_removal_stage_cleanup_attempts(request_id),
 resolution_id UUID NOT NULL CHECK(resolution_id<>'00000000-0000-0000-0000-000000000000' AND resolution_id<>request_id),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 revision TEXT NOT NULL UNIQUE CHECK(revision ~ '^[0-9a-f]{64}$'),
 snapshot_hash TEXT NOT NULL CHECK(snapshot_hash ~ '^[0-9a-f]{64}$'),
 sequence INTEGER NOT NULL CHECK(sequence>0),
 kind TEXT NOT NULL CHECK(kind IN ('withdraw','release')),
 observation_id UUID NOT NULL REFERENCES uem_netbird_removal_stage_cleanup_observations(id),
 journal JSONB NOT NULL CHECK(octet_length(journal::text)<=16384),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '2 minutes')
);
CREATE TABLE uem_netbird_removal_stage_cleanup_resolutions (
 request_id UUID PRIMARY KEY REFERENCES uem_netbird_removal_stage_cleanup_attempts(request_id),
 id UUID NOT NULL UNIQUE CHECK(id<>'00000000-0000-0000-0000-000000000000' AND id<>request_id),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 review_id UUID NOT NULL UNIQUE REFERENCES uem_netbird_removal_stage_cleanup_reviews(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(request_id,id)
);
CREATE TABLE uem_netbird_removal_stage_cleanup_controls (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 request_id UUID NOT NULL,
 resolution_id UUID NOT NULL,
 review_id UUID NOT NULL UNIQUE REFERENCES uem_netbird_removal_stage_cleanup_reviews(id),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 sequence INTEGER NOT NULL CHECK(sequence>0),
 kind TEXT NOT NULL CHECK(kind IN ('withdraw','release')),
 control_hash TEXT NOT NULL CHECK(control_hash ~ '^[0-9a-f]{64}$'),
 control JSONB NOT NULL CHECK(octet_length(control::text)<=16384),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(request_id,resolution_id) REFERENCES uem_netbird_removal_stage_cleanup_resolutions(request_id,id),
 UNIQUE(request_id,sequence)
);
CREATE TABLE uem_netbird_removal_stage_cleanup_control_results (
 attempt_id UUID PRIMARY KEY REFERENCES uem_netbird_removal_stage_cleanup_controls(id),
 response JSONB CHECK(octet_length(response::text)<=16384),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE uem_netbird_removal_stage_cleanup_release_proofs (
 request_id UUID PRIMARY KEY,
 resolution_id UUID NOT NULL,
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 attempt_id UUID REFERENCES uem_netbird_removal_stage_cleanup_control_results(attempt_id),
 observation_id UUID REFERENCES uem_netbird_removal_stage_cleanup_observations(id),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(request_id,resolution_id) REFERENCES uem_netbird_removal_stage_cleanup_resolutions(request_id,id),
 CHECK((attempt_id IS NULL)<>(observation_id IS NULL))
);

CREATE FUNCTION uem_netbird_removal_stage_cleanup_review_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_removal_stage_cleanups%ROWTYPE; a uem_netbird_removal_stage_cleanup_attempts%ROWTYPE;
 o uem_netbird_removal_stage_cleanup_observations%ROWTYPE; j JSONB;
BEGIN
 SELECT * INTO r FROM uem_netbird_removal_stage_cleanups WHERE id=NEW.request_id FOR UPDATE;
 IF NOT FOUND OR r.cancelled_at IS NOT NULL OR r.completed_at IS NOT NULL OR r.released_at IS NOT NULL
 THEN RAISE EXCEPTION 'NetBird stage cleanup is not awaiting resolution'; END IF;
 IF NEW.resolution_id=r.original_id OR NEW.resolution_id::text=r.stage_cleanup->'original'->>'release_id'
 THEN RAISE EXCEPTION 'NetBird stage cleanup resolution requires an independent UUID'; END IF;
 SELECT * INTO a FROM uem_netbird_removal_stage_cleanup_attempts WHERE request_id=r.id;
 SELECT * INTO o FROM uem_netbird_removal_stage_cleanup_observations WHERE id=NEW.observation_id AND request_id=r.id AND actor=NEW.actor;
 IF NOT FOUND OR o.recorded_at>NEW.created_at OR o.recorded_at<NEW.created_at-interval '10 seconds'
  OR NEW.created_at>clock_timestamp()+interval '5 seconds' OR NEW.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'NetBird stage cleanup review requires fresh evidence'; END IF;
 j=NEW.journal;
 IF j IS DISTINCT FROM jsonb_build_object('status',CASE WHEN NEW.kind='withdraw' THEN 'ready' ELSE 'unconfirmed' END,
  'revision',j->'revision','remaining',j->'remaining','pending_id',CASE WHEN NEW.kind='withdraw' THEN '' ELSE r.id::text END,
  'pending_hash',CASE WHEN NEW.kind='withdraw' THEN '' ELSE a.command_hash END,'can_release',NEW.kind='release')
  OR jsonb_typeof(j->'revision') IS DISTINCT FROM 'string' OR NOT coalesce(j->>'revision' ~ '^[0-9a-f]{64}$',false)
  OR jsonb_typeof(j->'remaining') IS DISTINCT FROM 'number' OR NOT coalesce(j->>'remaining' ~ '^[0-9]+$',false)
  OR (j->>'remaining')::integer NOT BETWEEN (CASE WHEN NEW.kind='withdraw' THEN 1 ELSE 0 END) AND 4096
 THEN RAISE EXCEPTION 'NetBird stage cleanup journal is not eligible'; END IF;
 IF (NEW.kind='withdraw' AND o.response->>'outcome' IS DISTINCT FROM 'missing')
  OR (NEW.kind='release' AND (o.response->>'outcome' IS DISTINCT FROM 'ok' OR o.response->'receipt'->>'status' IS DISTINCT FROM 'unconfirmed' OR o.response->>'release_id' IS DISTINCT FROM ''))
 THEN RAISE EXCEPTION 'NetBird stage cleanup review outcome is not eligible'; END IF;
 IF NEW.sequence<>(SELECT coalesce(max(sequence),0)+1 FROM uem_netbird_removal_stage_cleanup_controls WHERE request_id=r.id)
  OR EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanup_resolutions WHERE request_id=r.id AND id<>NEW.resolution_id)
  OR (NEW.kind='withdraw' AND EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanup_controls WHERE request_id=r.id AND kind='release'))
 THEN RAISE EXCEPTION 'NetBird stage cleanup resolution sequence changed'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_review_valid BEFORE INSERT ON uem_netbird_removal_stage_cleanup_reviews FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_review_valid();

CREATE FUNCTION uem_netbird_removal_stage_cleanup_resolution_valid() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM 1 FROM uem_netbird_removal_stage_cleanups WHERE id=NEW.request_id AND completed_at IS NULL AND released_at IS NULL AND cancelled_at IS NULL FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanup_reviews WHERE id=NEW.review_id AND request_id=NEW.request_id
  AND resolution_id=NEW.id AND actor=NEW.actor AND sequence=1 AND expires_at>clock_timestamp() AND created_at<=NEW.created_at)
 THEN RAISE EXCEPTION 'NetBird stage cleanup resolution requires current review'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_resolution_valid BEFORE INSERT ON uem_netbird_removal_stage_cleanup_resolutions FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_resolution_valid();

CREATE FUNCTION uem_netbird_removal_stage_cleanup_control_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_removal_stage_cleanups%ROWTYPE; a uem_netbird_removal_stage_cleanup_attempts%ROWTYPE;
 v uem_netbird_removal_stage_cleanup_reviews%ROWTYPE; c JSONB; expected JSONB;
BEGIN
 SELECT * INTO r FROM uem_netbird_removal_stage_cleanups WHERE id=NEW.request_id FOR UPDATE;
 IF NOT FOUND OR r.cancelled_at IS NOT NULL OR r.completed_at IS NOT NULL OR r.released_at IS NOT NULL
 THEN RAISE EXCEPTION 'NetBird stage cleanup is not awaiting resolution'; END IF;
 SELECT * INTO a FROM uem_netbird_removal_stage_cleanup_attempts WHERE request_id=r.id;
 SELECT * INTO v FROM uem_netbird_removal_stage_cleanup_reviews WHERE id=NEW.review_id AND request_id=r.id AND actor=NEW.actor
  AND resolution_id=NEW.resolution_id AND sequence=NEW.sequence AND kind=NEW.kind;
 IF NOT FOUND OR v.expires_at<=clock_timestamp() OR v.created_at>NEW.created_at
  OR NEW.sequence<>(SELECT coalesce(max(sequence),0)+1 FROM uem_netbird_removal_stage_cleanup_controls WHERE request_id=r.id)
  OR (NEW.kind='withdraw' AND EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanup_controls WHERE request_id=r.id AND kind='release'))
 THEN RAISE EXCEPTION 'NetBird stage cleanup control review changed'; END IF;
 c=NEW.control;
 expected=jsonb_build_object('version',CASE WHEN NEW.kind='withdraw' THEN 2 ELSE 1 END,
  'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',true,
  'certificate_hash',c->'certificate_hash','request_id',NEW.resolution_id::text,'kind',NEW.kind,
  'reference_id',r.id::text,'command_hash',a.command_hash,'issued_at',c->'issued_at','expires_at',c->'expires_at');
 IF NEW.kind='withdraw' THEN expected=expected||jsonb_build_object('revision',r.revision,'operation','cleanup-removal-stage'); END IF;
 IF c IS DISTINCT FROM expected OR jsonb_typeof(c->'certificate_hash') IS DISTINCT FROM 'string'
  OR NOT coalesce(c->>'certificate_hash' ~ '^[0-9a-f]{64}$',false)
  OR jsonb_typeof(c->'issued_at') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'expires_at') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'NetBird stage cleanup control does not match'; END IF;
 IF NOT ((c->>'expires_at')::timestamptz>(c->>'issued_at')::timestamptz
  AND (c->>'expires_at')::timestamptz<=(c->>'issued_at')::timestamptz+interval '10 seconds'
  AND (c->>'expires_at')::timestamptz<=v.expires_at AND (c->>'expires_at')::timestamptz>clock_timestamp()
  AND (c->>'issued_at')::timestamptz>=v.created_at AND (c->>'issued_at')::timestamptz<=NEW.created_at
  AND NEW.created_at<=clock_timestamp()+interval '5 seconds')
 THEN RAISE EXCEPTION 'NetBird stage cleanup control has expired'; END IF;
 PERFORM 1 FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id
  WHERE i.id=r.device_id::uuid AND i.tenant_id=r.tenant_id AND i.site_id=r.site_id AND i.revoked_at IS NULL
   AND i.certificate_hash=c->>'certificate_hash' AND i.certificate_expires_at>=(c->>'expires_at')::timestamptz
   AND q.desired_active AND q.revision=q.completed_revision FOR SHARE OF i,q;
 IF NOT FOUND OR c->>'certificate_hash' IS DISTINCT FROM (SELECT control->>'certificate_hash' FROM uem_netbird_removal_stage_cleanup_observations WHERE id=v.observation_id)
 THEN RAISE EXCEPTION 'NetBird stage cleanup resolution recipient changed'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_control_valid BEFORE INSERT ON uem_netbird_removal_stage_cleanup_controls FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_control_valid();

CREATE FUNCTION uem_netbird_removal_stage_cleanup_control_result_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a uem_netbird_removal_stage_cleanup_controls%ROWTYPE; r uem_netbird_removal_stage_cleanups%ROWTYPE;
 c JSONB; p JSONB; receipt JSONB; state JSONB;
BEGIN
 SELECT * INTO a FROM uem_netbird_removal_stage_cleanup_controls WHERE id=NEW.attempt_id;
 IF NOT FOUND OR NEW.recorded_at<a.created_at OR NEW.recorded_at>clock_timestamp()+interval '5 seconds'
 THEN RAISE EXCEPTION 'NetBird stage cleanup control result has no attempt'; END IF;
 SELECT * INTO r FROM uem_netbird_removal_stage_cleanups WHERE id=a.request_id FOR UPDATE;
 c=a.control; p=NEW.response;
 IF p IS NULL THEN RETURN NEW; END IF;
 state=jsonb_build_object('status','','revision','','remaining',0,'pending_id','','pending_hash','','can_release',false);
 receipt=jsonb_build_object('version',0,'request_id','','device_id','','revision','','command_hash','','operation','','status','');
 IF p->>'outcome'='ok' THEN
  receipt=jsonb_build_object('version',1,'request_id',r.id::text,'device_id',r.device_id,'revision',r.revision,
   'command_hash',c->>'command_hash','operation','cleanup-removal-stage','status',CASE WHEN a.kind='withdraw' THEN 'withdrawn' ELSE 'unconfirmed' END);
  IF p->>'release_id' IS DISTINCT FROM a.resolution_id::text THEN RAISE EXCEPTION 'NetBird stage cleanup control result has foreign resolution'; END IF;
 ELSIF NOT coalesce(p->>'outcome' IN ('missing','blocked','conflict','unavailable'),false) OR p->>'release_id' IS DISTINCT FROM ''
 THEN RAISE EXCEPTION 'NetBird stage cleanup control outcome is invalid'; END IF;
 IF p IS DISTINCT FROM jsonb_build_object('version',c->'version','device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,
  'individual',true,'certificate_hash',c->'certificate_hash','request_id',a.resolution_id::text,'request_hash',a.control_hash,
  'kind',a.kind,'outcome',p->'outcome','state',state,'receipt',receipt,'release_id',p->'release_id')
 THEN RAISE EXCEPTION 'NetBird stage cleanup control response does not match'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_control_result_valid BEFORE INSERT ON uem_netbird_removal_stage_cleanup_control_results FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_control_result_valid();

CREATE FUNCTION uem_netbird_removal_stage_cleanup_release_proof_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p JSONB; observed TIMESTAMPTZ; status TEXT;
BEGIN
 PERFORM 1 FROM uem_netbird_removal_stage_cleanups WHERE id=NEW.request_id AND completed_at IS NULL AND released_at IS NULL AND cancelled_at IS NULL FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'NetBird stage cleanup no longer awaits resolution'; END IF;
 IF NEW.attempt_id IS NOT NULL THEN
  SELECT v.response,v.recorded_at INTO p,observed FROM uem_netbird_removal_stage_cleanup_control_results v JOIN uem_netbird_removal_stage_cleanup_controls a ON a.id=v.attempt_id
   WHERE a.id=NEW.attempt_id AND a.request_id=NEW.request_id AND a.resolution_id=NEW.resolution_id;
 ELSE
  SELECT response,recorded_at INTO p,observed FROM uem_netbird_removal_stage_cleanup_observations WHERE id=NEW.observation_id AND request_id=NEW.request_id;
 END IF;
 status=p->'receipt'->>'status';
 IF p->>'outcome' IS DISTINCT FROM 'ok' OR p->>'release_id' IS DISTINCT FROM NEW.resolution_id::text
  OR NOT coalesce(status IN ('unconfirmed','withdrawn'),false)
  OR NOT EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanup_controls WHERE request_id=NEW.request_id AND resolution_id=NEW.resolution_id AND created_at<=observed AND kind=CASE WHEN status='withdrawn' THEN 'withdraw' ELSE 'release' END)
  OR observed IS NULL OR observed>NEW.recorded_at OR NEW.recorded_at>clock_timestamp()+interval '5 seconds'
 THEN RAISE EXCEPTION 'NetBird stage cleanup release requires exact owned proof'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_release_proof_valid BEFORE INSERT ON uem_netbird_removal_stage_cleanup_release_proofs FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_release_proof_valid();

CREATE FUNCTION uem_netbird_removal_stage_cleanup_release_required() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' AND NEW.released_at IS NOT NULL THEN RAISE EXCEPTION 'NetBird stage cleanup cannot begin released'; END IF;
 IF TG_OP='UPDATE' AND OLD.released_at IS NULL AND NEW.released_at IS NOT NULL AND NOT EXISTS(
  SELECT 1 FROM uem_netbird_removal_stage_cleanup_release_proofs WHERE request_id=NEW.id AND resolution_id=NEW.resolution_id AND actor=NEW.released_by AND recorded_at=NEW.released_at)
 THEN RAISE EXCEPTION 'NetBird stage cleanup release requires retained evidence'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_release_required BEFORE INSERT OR UPDATE ON uem_netbird_removal_stage_cleanups FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_release_required();

CREATE OR REPLACE FUNCTION uem_netbird_removal_stage_cleanup_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NetBird stage cleanup requests are permanent'; END IF;
 IF (to_jsonb(NEW)-ARRAY['cancellation_id','cancelled_by','cancelled_at','completed_at','released_at','released_by','resolution_id'])
  IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['cancellation_id','cancelled_by','cancelled_at','completed_at','released_at','released_by','resolution_id'])
  OR ((OLD.cancelled_at IS NOT NULL OR OLD.completed_at IS NOT NULL OR OLD.released_at IS NOT NULL) AND NEW IS DISTINCT FROM OLD)
 THEN RAISE EXCEPTION 'NetBird stage cleanup intent and terminal evidence are immutable'; END IF;
 IF NEW.cancelled_at IS NOT NULL AND OLD.cancelled_at IS NULL AND EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanup_attempts WHERE request_id=NEW.id)
 THEN RAISE EXCEPTION 'NetBird stage cleanup delivery cannot be cancelled'; END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION uem_netbird_removal_stage_cleanup_review_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird stage cleanup resolution evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_review_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_stage_cleanup_reviews FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_review_immutable();

CREATE FUNCTION uem_netbird_removal_stage_cleanup_resolution_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird stage cleanup resolution evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_resolution_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_stage_cleanup_resolutions FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_resolution_immutable();

CREATE FUNCTION uem_netbird_removal_stage_cleanup_control_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird stage cleanup resolution evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_control_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_stage_cleanup_controls FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_control_immutable();

CREATE FUNCTION uem_netbird_removal_stage_cleanup_control_result_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird stage cleanup resolution evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_control_result_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_stage_cleanup_control_results FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_control_result_immutable();

CREATE FUNCTION uem_netbird_removal_stage_cleanup_release_proof_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird stage cleanup resolution evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_release_proof_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_stage_cleanup_release_proofs FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_release_proof_immutable();


CREATE OR REPLACE FUNCTION uem_netbird_removal_stage_cleanup_attempt_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_removal_stage_cleanups%ROWTYPE; valid BOOLEAN;
BEGIN
 SELECT * INTO r FROM uem_netbird_removal_stage_cleanups WHERE id=NEW.request_id FOR UPDATE;
 IF NOT FOUND OR r.cancelled_at IS NOT NULL OR r.completed_at IS NOT NULL OR r.released_at IS NOT NULL OR clock_timestamp()>=r.expires_at
 THEN RAISE EXCEPTION 'NetBird stage cleanup request is unavailable'; END IF;
 IF NEW.issued_at<r.requested_at OR NEW.issued_at>clock_timestamp()+interval '5 seconds'
  OR NEW.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'NetBird stage cleanup attempt requires fresh command times'; END IF;
 PERFORM 1 FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id
  WHERE i.id=r.device_id::uuid FOR SHARE OF i,q;
 SELECT EXISTS(SELECT 1 FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id
  WHERE i.id=r.device_id::uuid AND i.tenant_id=r.tenant_id AND i.site_id=r.site_id
   AND i.certificate_hash=NEW.certificate_hash AND i.certificate_expires_at>=NEW.expires_at
   AND i.revoked_at IS NULL AND q.desired_active AND q.revision=q.completed_revision) INTO valid;
 IF NOT valid THEN RAISE EXCEPTION 'NetBird stage cleanup recipient changed'; END IF;
 RETURN NEW;
END $$;

-- A pre-delivery dispatch stop retains the device barrier until explicit cancel.
CREATE TABLE uem_netbird_removal_stage_cleanup_dispatch_stops (
 request_id UUID PRIMARY KEY REFERENCES uem_netbird_removal_stage_cleanups(id),
 reason TEXT NOT NULL CHECK(reason IN ('expired','not_authorized','source_changed')),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION uem_netbird_removal_stage_cleanup_dispatch_stop_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird stage cleanup dispatch stops are permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_dispatch_stop_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_stage_cleanup_dispatch_stops FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_dispatch_stop_immutable();
CREATE FUNCTION uem_netbird_removal_stage_cleanup_dispatch_stop_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_removal_stage_cleanups%ROWTYPE;
BEGIN
 SELECT * INTO r FROM uem_netbird_removal_stage_cleanups WHERE id=NEW.request_id FOR UPDATE;
 IF NOT FOUND OR r.cancelled_at IS NOT NULL OR r.completed_at IS NOT NULL OR r.released_at IS NOT NULL
  OR EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanup_attempts WHERE request_id=r.id)
  OR NEW.recorded_at<r.requested_at OR NEW.recorded_at>clock_timestamp()+interval '5 seconds'
 THEN RAISE EXCEPTION 'NetBird stage cleanup cannot stop before delivery'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_dispatch_stop_valid BEFORE INSERT ON uem_netbird_removal_stage_cleanup_dispatch_stops FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_dispatch_stop_valid();
CREATE FUNCTION uem_netbird_removal_stage_cleanup_dispatch_required() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM 1 FROM uem_netbird_removal_stage_cleanups WHERE id=NEW.request_id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanup_dispatch_stops WHERE request_id=NEW.request_id)
 THEN RAISE EXCEPTION 'NetBird stage cleanup dispatch was stopped'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_stage_cleanup_dispatch_required BEFORE INSERT ON uem_netbird_removal_stage_cleanup_attempts FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_stage_cleanup_dispatch_required();

CREATE OR REPLACE FUNCTION uem_netbird_registration_admission() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(684629916,hashtext(NEW.id::text));
 PERFORM pg_advisory_xact_lock(684629914,hashtext(NEW.device_id));
 IF (TG_TABLE_NAME<>'uem_netbird_operations' AND EXISTS(SELECT 1 FROM uem_netbird_operations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))))
  OR (TG_TABLE_NAME<>'uem_netbird_registrations' AND EXISTS(SELECT 1 FROM uem_netbird_registrations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))))
  OR (TG_TABLE_NAME<>'uem_netbird_installations' AND EXISTS(SELECT 1 FROM uem_netbird_installations WHERE id=NEW.id OR (device_id=NEW.device_id AND cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL)))
  OR (TG_TABLE_NAME<>'uem_netbird_removals' AND EXISTS(SELECT 1 FROM uem_netbird_removals WHERE id=NEW.id OR (device_id=NEW.device_id AND cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL)))
  OR (TG_TABLE_NAME<>'uem_netbird_removal_recoveries' AND EXISTS(SELECT 1 FROM uem_netbird_removal_recoveries WHERE id=NEW.id OR (device_id=NEW.device_id AND cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL)))
  OR (TG_TABLE_NAME<>'uem_netbird_removal_absences' AND EXISTS(SELECT 1 FROM uem_netbird_removal_absences WHERE id=NEW.id OR (device_id=NEW.device_id AND cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL)))
  OR (TG_TABLE_NAME<>'uem_netbird_removal_stage_cleanups' AND EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanups WHERE id=NEW.id OR (device_id=NEW.device_id AND cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL)))
 THEN RAISE EXCEPTION 'NetBird request conflicts with a retained operation'; END IF;
 RETURN NEW;
END $$;
