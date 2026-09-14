-- A released uncertain removal remains distinct from a completed native removal.
ALTER TABLE uem_netbird_removals ADD COLUMN released_at TIMESTAMPTZ,
 ADD COLUMN released_by TEXT, ADD COLUMN resolution_id UUID;
ALTER TABLE uem_netbird_removals ADD CONSTRAINT uem_netbird_removal_release_metadata CHECK(
 (released_at IS NULL AND released_by IS NULL AND resolution_id IS NULL) OR
 (released_at IS NOT NULL AND released_by IS NOT NULL AND resolution_id IS NOT NULL
  AND octet_length(released_by) BETWEEN 1 AND 255 AND released_at>=requested_at
  AND completed_at IS NULL AND cancelled_at IS NULL));
DROP INDEX uem_netbird_removals_barrier;
CREATE UNIQUE INDEX uem_netbird_removals_barrier ON uem_netbird_removals(device_id)
 WHERE cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL;

CREATE TABLE uem_netbird_removal_reviews (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 request_id UUID NOT NULL REFERENCES uem_netbird_removal_attempts(request_id),
 resolution_id UUID NOT NULL CHECK(resolution_id<>'00000000-0000-0000-0000-000000000000' AND resolution_id<>request_id),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 revision TEXT NOT NULL UNIQUE CHECK(revision ~ '^[0-9a-f]{64}$'),
 snapshot_hash TEXT NOT NULL CHECK(snapshot_hash ~ '^[0-9a-f]{64}$'),
 sequence INTEGER NOT NULL CHECK(sequence>0),
 kind TEXT NOT NULL CHECK(kind IN ('withdraw','release')),
 observation_id UUID NOT NULL REFERENCES uem_netbird_removal_observations(id),
 journal JSONB NOT NULL CHECK(octet_length(journal::text)<=16384),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '2 minutes')
);
CREATE TABLE uem_netbird_removal_resolutions (
 request_id UUID PRIMARY KEY REFERENCES uem_netbird_removal_attempts(request_id),
 id UUID NOT NULL UNIQUE CHECK(id<>'00000000-0000-0000-0000-000000000000' AND id<>request_id),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 review_id UUID NOT NULL UNIQUE REFERENCES uem_netbird_removal_reviews(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(request_id,id)
);
CREATE TABLE uem_netbird_removal_controls (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 request_id UUID NOT NULL,
 resolution_id UUID NOT NULL,
 review_id UUID NOT NULL UNIQUE REFERENCES uem_netbird_removal_reviews(id),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 sequence INTEGER NOT NULL CHECK(sequence>0),
 kind TEXT NOT NULL CHECK(kind IN ('withdraw','release')),
 control_hash TEXT NOT NULL CHECK(control_hash ~ '^[0-9a-f]{64}$'),
 control JSONB NOT NULL CHECK(octet_length(control::text)<=16384),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(request_id,resolution_id) REFERENCES uem_netbird_removal_resolutions(request_id,id),
 UNIQUE(request_id,sequence)
);
CREATE TABLE uem_netbird_removal_control_results (
 attempt_id UUID PRIMARY KEY REFERENCES uem_netbird_removal_controls(id),
 response JSONB CHECK(octet_length(response::text)<=16384),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE uem_netbird_removal_release_proofs (
 request_id UUID PRIMARY KEY,
 resolution_id UUID NOT NULL,
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 attempt_id UUID REFERENCES uem_netbird_removal_control_results(attempt_id),
 observation_id UUID REFERENCES uem_netbird_removal_observations(id),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(request_id,resolution_id) REFERENCES uem_netbird_removal_resolutions(request_id,id),
 CHECK((attempt_id IS NULL)<>(observation_id IS NULL))
);

CREATE FUNCTION uem_netbird_removal_review_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_removals%ROWTYPE; a uem_netbird_removal_attempts%ROWTYPE;
 o uem_netbird_removal_observations%ROWTYPE; j JSONB;
BEGIN
 SELECT * INTO r FROM uem_netbird_removals WHERE id=NEW.request_id FOR UPDATE;
 IF NOT FOUND OR r.cancelled_at IS NOT NULL OR r.completed_at IS NOT NULL OR r.released_at IS NOT NULL
 THEN RAISE EXCEPTION 'NetBird removal is not awaiting resolution'; END IF;
 SELECT * INTO a FROM uem_netbird_removal_attempts WHERE request_id=r.id;
 SELECT * INTO o FROM uem_netbird_removal_observations WHERE id=NEW.observation_id AND request_id=r.id AND actor=NEW.actor;
 IF NOT FOUND OR o.recorded_at>NEW.created_at OR o.recorded_at<NEW.created_at-interval '10 seconds'
  OR NEW.created_at>clock_timestamp()+interval '5 seconds' OR NEW.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'NetBird removal review requires fresh evidence'; END IF;
 j=NEW.journal;
 IF j IS DISTINCT FROM jsonb_build_object('status',CASE WHEN NEW.kind='withdraw' THEN 'ready' ELSE 'unconfirmed' END,
  'revision',j->'revision','remaining',j->'remaining','pending_id',CASE WHEN NEW.kind='withdraw' THEN '' ELSE r.id::text END,
  'pending_hash',CASE WHEN NEW.kind='withdraw' THEN '' ELSE a.command_hash END,'can_release',NEW.kind='release')
  OR jsonb_typeof(j->'revision') IS DISTINCT FROM 'string' OR NOT coalesce(j->>'revision' ~ '^[0-9a-f]{64}$',false)
  OR jsonb_typeof(j->'remaining') IS DISTINCT FROM 'number' OR NOT coalesce(j->>'remaining' ~ '^[0-9]+$',false)
  OR (j->>'remaining')::integer NOT BETWEEN (CASE WHEN NEW.kind='withdraw' THEN 1 ELSE 0 END) AND 4096
 THEN RAISE EXCEPTION 'NetBird removal journal is not eligible'; END IF;
 IF (NEW.kind='withdraw' AND o.response->>'outcome' IS DISTINCT FROM 'missing')
  OR (NEW.kind='release' AND (o.response->>'outcome' IS DISTINCT FROM 'ok' OR o.response->'receipt'->>'status' IS DISTINCT FROM 'unconfirmed' OR o.response->>'release_id' IS DISTINCT FROM ''))
 THEN RAISE EXCEPTION 'NetBird removal review outcome is not eligible'; END IF;
 IF NEW.sequence<>(SELECT coalesce(max(sequence),0)+1 FROM uem_netbird_removal_controls WHERE request_id=r.id)
  OR EXISTS(SELECT 1 FROM uem_netbird_removal_resolutions WHERE request_id=r.id AND id<>NEW.resolution_id)
  OR (NEW.kind='withdraw' AND EXISTS(SELECT 1 FROM uem_netbird_removal_controls WHERE request_id=r.id AND kind='release'))
 THEN RAISE EXCEPTION 'NetBird removal resolution sequence changed'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_review_valid BEFORE INSERT ON uem_netbird_removal_reviews FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_review_valid();

CREATE FUNCTION uem_netbird_removal_resolution_valid() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM 1 FROM uem_netbird_removals WHERE id=NEW.request_id AND completed_at IS NULL AND released_at IS NULL AND cancelled_at IS NULL FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM uem_netbird_removal_reviews WHERE id=NEW.review_id AND request_id=NEW.request_id
  AND resolution_id=NEW.id AND actor=NEW.actor AND sequence=1 AND expires_at>clock_timestamp() AND created_at<=NEW.created_at)
 THEN RAISE EXCEPTION 'NetBird removal resolution requires current review'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_resolution_valid BEFORE INSERT ON uem_netbird_removal_resolutions FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_resolution_valid();

CREATE FUNCTION uem_netbird_removal_control_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_removals%ROWTYPE; a uem_netbird_removal_attempts%ROWTYPE;
 v uem_netbird_removal_reviews%ROWTYPE; c JSONB; expected JSONB;
BEGIN
 SELECT * INTO r FROM uem_netbird_removals WHERE id=NEW.request_id FOR UPDATE;
 IF NOT FOUND OR r.cancelled_at IS NOT NULL OR r.completed_at IS NOT NULL OR r.released_at IS NOT NULL
 THEN RAISE EXCEPTION 'NetBird removal is not awaiting resolution'; END IF;
 SELECT * INTO a FROM uem_netbird_removal_attempts WHERE request_id=r.id;
 SELECT * INTO v FROM uem_netbird_removal_reviews WHERE id=NEW.review_id AND request_id=r.id AND actor=NEW.actor
  AND resolution_id=NEW.resolution_id AND sequence=NEW.sequence AND kind=NEW.kind;
 IF NOT FOUND OR v.expires_at<=clock_timestamp() OR v.created_at>NEW.created_at
  OR NEW.sequence<>(SELECT coalesce(max(sequence),0)+1 FROM uem_netbird_removal_controls WHERE request_id=r.id)
  OR (NEW.kind='withdraw' AND EXISTS(SELECT 1 FROM uem_netbird_removal_controls WHERE request_id=r.id AND kind='release'))
 THEN RAISE EXCEPTION 'NetBird removal control review changed'; END IF;
 c=NEW.control;
 expected=jsonb_build_object('version',CASE WHEN NEW.kind='withdraw' THEN 2 ELSE 1 END,
  'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,'individual',true,
  'certificate_hash',c->'certificate_hash','request_id',NEW.resolution_id::text,'kind',NEW.kind,
  'reference_id',r.id::text,'command_hash',a.command_hash,'issued_at',c->'issued_at','expires_at',c->'expires_at');
 IF NEW.kind='withdraw' THEN expected=expected||jsonb_build_object('revision',r.revision,'operation','uninstall'); END IF;
 IF c IS DISTINCT FROM expected OR jsonb_typeof(c->'certificate_hash') IS DISTINCT FROM 'string'
  OR NOT coalesce(c->>'certificate_hash' ~ '^[0-9a-f]{64}$',false)
  OR jsonb_typeof(c->'issued_at') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'expires_at') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'NetBird removal control does not match'; END IF;
 IF NOT ((c->>'expires_at')::timestamptz>(c->>'issued_at')::timestamptz
  AND (c->>'expires_at')::timestamptz<=(c->>'issued_at')::timestamptz+interval '10 seconds'
  AND (c->>'expires_at')::timestamptz<=v.expires_at AND (c->>'expires_at')::timestamptz>clock_timestamp()
  AND (c->>'issued_at')::timestamptz>=v.created_at AND (c->>'issued_at')::timestamptz<=NEW.created_at
  AND NEW.created_at<=clock_timestamp()+interval '5 seconds')
 THEN RAISE EXCEPTION 'NetBird removal control has expired'; END IF;
 PERFORM 1 FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id
  WHERE i.id=r.device_id::uuid AND i.tenant_id=r.tenant_id AND i.site_id=r.site_id AND i.revoked_at IS NULL
   AND i.certificate_hash=c->>'certificate_hash' AND i.certificate_expires_at>=(c->>'expires_at')::timestamptz
   AND q.desired_active AND q.revision=q.completed_revision FOR SHARE OF i,q;
 IF NOT FOUND OR c->>'certificate_hash' IS DISTINCT FROM (SELECT control->>'certificate_hash' FROM uem_netbird_removal_observations WHERE id=v.observation_id)
 THEN RAISE EXCEPTION 'NetBird removal resolution recipient changed'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_control_valid BEFORE INSERT ON uem_netbird_removal_controls FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_control_valid();

CREATE FUNCTION uem_netbird_removal_control_result_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a uem_netbird_removal_controls%ROWTYPE; r uem_netbird_removals%ROWTYPE;
 c JSONB; p JSONB; receipt JSONB; state JSONB;
BEGIN
 SELECT * INTO a FROM uem_netbird_removal_controls WHERE id=NEW.attempt_id;
 IF NOT FOUND OR NEW.recorded_at<a.created_at OR NEW.recorded_at>clock_timestamp()+interval '5 seconds'
 THEN RAISE EXCEPTION 'NetBird removal control result has no attempt'; END IF;
 SELECT * INTO r FROM uem_netbird_removals WHERE id=a.request_id FOR UPDATE;
 c=a.control; p=NEW.response;
 IF p IS NULL THEN RETURN NEW; END IF;
 state=jsonb_build_object('status','','revision','','remaining',0,'pending_id','','pending_hash','','can_release',false);
 receipt=jsonb_build_object('version',0,'request_id','','device_id','','revision','','command_hash','','operation','','status','');
 IF p->>'outcome'='ok' THEN
  receipt=jsonb_build_object('version',1,'request_id',r.id::text,'device_id',r.device_id,'revision',r.revision,
   'command_hash',c->>'command_hash','operation','uninstall','status',CASE WHEN a.kind='withdraw' THEN 'withdrawn' ELSE 'unconfirmed' END);
  IF p->>'release_id' IS DISTINCT FROM a.resolution_id::text THEN RAISE EXCEPTION 'NetBird removal control result has foreign resolution'; END IF;
 ELSIF NOT coalesce(p->>'outcome' IN ('missing','blocked','conflict','unavailable'),false) OR p->>'release_id' IS DISTINCT FROM ''
 THEN RAISE EXCEPTION 'NetBird removal control outcome is invalid'; END IF;
 IF p IS DISTINCT FROM jsonb_build_object('version',c->'version','device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,
  'individual',true,'certificate_hash',c->'certificate_hash','request_id',a.resolution_id::text,'request_hash',a.control_hash,
  'kind',a.kind,'outcome',p->'outcome','state',state,'receipt',receipt,'release_id',p->'release_id')
 THEN RAISE EXCEPTION 'NetBird removal control response does not match'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_control_result_valid BEFORE INSERT ON uem_netbird_removal_control_results FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_control_result_valid();

CREATE FUNCTION uem_netbird_removal_release_proof_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p JSONB; observed TIMESTAMPTZ; status TEXT;
BEGIN
 PERFORM 1 FROM uem_netbird_removals WHERE id=NEW.request_id AND completed_at IS NULL AND released_at IS NULL AND cancelled_at IS NULL FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'NetBird removal no longer awaits resolution'; END IF;
 IF NEW.attempt_id IS NOT NULL THEN
  SELECT v.response,v.recorded_at INTO p,observed FROM uem_netbird_removal_control_results v JOIN uem_netbird_removal_controls a ON a.id=v.attempt_id
   WHERE a.id=NEW.attempt_id AND a.request_id=NEW.request_id AND a.resolution_id=NEW.resolution_id;
 ELSE
  SELECT response,recorded_at INTO p,observed FROM uem_netbird_removal_observations WHERE id=NEW.observation_id AND request_id=NEW.request_id;
 END IF;
 status=p->'receipt'->>'status';
 IF p->>'outcome' IS DISTINCT FROM 'ok' OR p->>'release_id' IS DISTINCT FROM NEW.resolution_id::text
  OR NOT coalesce(status IN ('unconfirmed','withdrawn'),false)
  OR NOT EXISTS(SELECT 1 FROM uem_netbird_removal_controls WHERE request_id=NEW.request_id AND resolution_id=NEW.resolution_id AND created_at<=observed AND kind=CASE WHEN status='withdrawn' THEN 'withdraw' ELSE 'release' END)
  OR observed IS NULL OR observed>NEW.recorded_at OR NEW.recorded_at>clock_timestamp()+interval '5 seconds'
 THEN RAISE EXCEPTION 'NetBird removal release requires exact owned proof'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_release_proof_valid BEFORE INSERT ON uem_netbird_removal_release_proofs FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_release_proof_valid();

CREATE FUNCTION uem_netbird_removal_release_required() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' AND NEW.released_at IS NOT NULL THEN RAISE EXCEPTION 'NetBird removal cannot begin released'; END IF;
 IF TG_OP='UPDATE' AND OLD.released_at IS NULL AND NEW.released_at IS NOT NULL AND NOT EXISTS(
  SELECT 1 FROM uem_netbird_removal_release_proofs WHERE request_id=NEW.id AND resolution_id=NEW.resolution_id AND actor=NEW.released_by AND recorded_at=NEW.released_at)
 THEN RAISE EXCEPTION 'NetBird removal release requires retained evidence'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_release_required BEFORE INSERT OR UPDATE ON uem_netbird_removals FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_release_required();

CREATE OR REPLACE FUNCTION uem_netbird_removal_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NetBird removal requests are permanent'; END IF;
 IF (to_jsonb(NEW)-ARRAY['cancellation_id','cancelled_by','cancelled_at','completed_at','released_at','released_by','resolution_id'])
  IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['cancellation_id','cancelled_by','cancelled_at','completed_at','released_at','released_by','resolution_id'])
  OR ((OLD.cancelled_at IS NOT NULL OR OLD.completed_at IS NOT NULL OR OLD.released_at IS NOT NULL) AND NEW IS DISTINCT FROM OLD)
 THEN RAISE EXCEPTION 'NetBird removal intent and terminal evidence are immutable'; END IF;
 IF NEW.cancelled_at IS NOT NULL AND OLD.cancelled_at IS NULL AND EXISTS(SELECT 1 FROM uem_netbird_removal_attempts WHERE request_id=NEW.id)
 THEN RAISE EXCEPTION 'NetBird removal delivery cannot be cancelled'; END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION uem_netbird_registration_admission() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(684629916,hashtext(NEW.id::text));
 PERFORM pg_advisory_xact_lock(684629914,hashtext(NEW.device_id));
 IF (TG_TABLE_NAME<>'uem_netbird_operations' AND EXISTS(SELECT 1 FROM uem_netbird_operations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))))
  OR (TG_TABLE_NAME<>'uem_netbird_registrations' AND EXISTS(SELECT 1 FROM uem_netbird_registrations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))))
  OR (TG_TABLE_NAME<>'uem_netbird_installations' AND EXISTS(SELECT 1 FROM uem_netbird_installations WHERE id=NEW.id OR (device_id=NEW.device_id AND cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL)))
  OR (TG_TABLE_NAME<>'uem_netbird_removals' AND EXISTS(SELECT 1 FROM uem_netbird_removals WHERE id=NEW.id OR (device_id=NEW.device_id AND cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL)))
 THEN RAISE EXCEPTION 'NetBird request conflicts with a retained operation'; END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION uem_netbird_removal_review_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird removal resolution evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_review_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_reviews FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_review_immutable();

CREATE FUNCTION uem_netbird_removal_resolution_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird removal resolution evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_resolution_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_resolutions FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_resolution_immutable();

CREATE FUNCTION uem_netbird_removal_control_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird removal resolution evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_control_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_controls FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_control_immutable();

CREATE FUNCTION uem_netbird_removal_control_result_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird removal resolution evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_control_result_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_control_results FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_control_result_immutable();

CREATE FUNCTION uem_netbird_removal_release_proof_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird removal resolution evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_release_proof_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_release_proofs FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_release_proof_immutable();
