-- Independent manifest-backed continuation requests. Their original uninstall
-- and owned release evidence remain immutable; this schema grants no delivery.
CREATE TABLE uem_netbird_removal_recoveries (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 original_id UUID NOT NULL REFERENCES uem_netbird_removal_release_proofs(request_id) CHECK(original_id<>id),
 device_id TEXT NOT NULL CHECK(device_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND device_id<>'00000000-0000-0000-0000-000000000000'),
 tenant_id BIGINT NOT NULL CHECK(tenant_id>0),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 revision TEXT NOT NULL CHECK(revision ~ '^[0-9a-f]{64}$'),
 journal_revision TEXT NOT NULL CHECK(journal_revision ~ '^[0-9a-f]{64}$'),
 recovery_digest TEXT NOT NULL CHECK(recovery_digest ~ '^[0-9a-f]{64}$'),
 recovery JSONB NOT NULL CHECK(octet_length(recovery::text)<=8192),
 requested_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 cancellation_id UUID UNIQUE CHECK(cancellation_id<>'00000000-0000-0000-0000-000000000000'::uuid AND cancellation_id<>id AND cancellation_id<>original_id),
 cancelled_by TEXT CHECK(octet_length(cancelled_by) BETWEEN 1 AND 255),
 cancelled_at TIMESTAMPTZ,
 CHECK(expires_at>requested_at AND expires_at<=requested_at+interval '10 minutes'),
 CHECK((cancellation_id IS NULL)=(cancelled_by IS NULL) AND (cancellation_id IS NULL)=(cancelled_at IS NULL)),
 CHECK(cancelled_at IS NULL OR cancelled_at>=requested_at),
 CHECK(cancellation_id IS NULL OR cancellation_id::text IS DISTINCT FROM recovery->'original'->>'release_id')
);
CREATE UNIQUE INDEX uem_netbird_removal_recoveries_barrier ON uem_netbird_removal_recoveries(device_id) WHERE cancelled_at IS NULL;
CREATE INDEX uem_netbird_removal_recoveries_history ON uem_netbird_removal_recoveries(tenant_id,site_id,device_id,requested_at DESC,id DESC);

CREATE FUNCTION uem_netbird_removal_recovery_initial() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_removals%ROWTYPE; a uem_netbird_removal_attempts%ROWTYPE;
 proof uem_netbird_removal_release_proofs%ROWTYPE; response JSONB; observed TIMESTAMPTZ; original JSONB;
BEGIN
 PERFORM pg_advisory_xact_lock(684629916,hashtext(NEW.id::text));
 PERFORM pg_advisory_xact_lock(684629914,hashtext(NEW.device_id));
 IF NEW.cancelled_at IS NOT NULL THEN RAISE EXCEPTION 'NetBird recovery cannot begin cancelled'; END IF;
 SELECT * INTO r FROM uem_netbird_removals WHERE id=NEW.original_id FOR SHARE;
 IF NOT FOUND OR r.device_id<>NEW.device_id OR r.tenant_id<>NEW.tenant_id OR r.site_id<>NEW.site_id
  OR r.cancelled_at IS NOT NULL OR r.completed_at IS NOT NULL OR r.released_at IS NULL
  OR r.resolution_id IS NULL OR NEW.id=r.resolution_id OR r.descriptor->>'platform' IS DISTINCT FROM 'macos'
 THEN RAISE EXCEPTION 'NetBird recovery requires the exact released original removal'; END IF;
 SELECT * INTO a FROM uem_netbird_removal_attempts WHERE request_id=r.id;
 IF NOT FOUND THEN RAISE EXCEPTION 'NetBird recovery requires an original native attempt'; END IF;
 SELECT * INTO proof FROM uem_netbird_removal_release_proofs WHERE request_id=r.id AND resolution_id=r.resolution_id;
 IF NOT FOUND OR proof.actor<>r.released_by OR proof.recorded_at<>r.released_at OR proof.recorded_at>NEW.requested_at
 THEN RAISE EXCEPTION 'NetBird recovery requires owned original release proof'; END IF;
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
 THEN RAISE EXCEPTION 'NetBird recovery cannot use withdrawn or foreign removal evidence'; END IF;
 original=jsonb_build_object('request_id',r.id::text,'command_hash',a.command_hash,'revision',r.revision,'release_id',r.resolution_id::text,'removal',r.descriptor);
 IF NEW.recovery IS DISTINCT FROM jsonb_build_object('original',original,'mode','manifest','journal_revision',NEW.journal_revision,'state_digest',NEW.recovery->'state_digest')
  OR jsonb_typeof(NEW.recovery->'state_digest') IS DISTINCT FROM 'string'
  OR NOT coalesce(NEW.recovery->>'state_digest' ~ '^[0-9a-f]{64}$',false)
 THEN RAISE EXCEPTION 'NetBird recovery descriptor does not match original evidence'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_recovery_initial BEFORE INSERT ON uem_netbird_removal_recoveries
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_recovery_initial();

CREATE FUNCTION uem_netbird_removal_recovery_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NetBird recovery requests are permanent'; END IF;
 IF (to_jsonb(NEW)-ARRAY['cancellation_id','cancelled_by','cancelled_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['cancellation_id','cancelled_by','cancelled_at'])
  OR (OLD.cancelled_at IS NOT NULL AND NEW IS DISTINCT FROM OLD)
 THEN RAISE EXCEPTION 'NetBird recovery intent and cancellation are immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_recovery_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_recoveries
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_recovery_immutable();

-- Extend the existing permanent request UUID and unresolved-device namespace.
CREATE OR REPLACE FUNCTION uem_netbird_registration_admission() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(684629916,hashtext(NEW.id::text));
 PERFORM pg_advisory_xact_lock(684629914,hashtext(NEW.device_id));
 IF (TG_TABLE_NAME<>'uem_netbird_operations' AND EXISTS(SELECT 1 FROM uem_netbird_operations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))))
  OR (TG_TABLE_NAME<>'uem_netbird_registrations' AND EXISTS(SELECT 1 FROM uem_netbird_registrations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))))
  OR (TG_TABLE_NAME<>'uem_netbird_installations' AND EXISTS(SELECT 1 FROM uem_netbird_installations WHERE id=NEW.id OR (device_id=NEW.device_id AND cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL)))
  OR (TG_TABLE_NAME<>'uem_netbird_removals' AND EXISTS(SELECT 1 FROM uem_netbird_removals WHERE id=NEW.id OR (device_id=NEW.device_id AND cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL)))
  OR (TG_TABLE_NAME<>'uem_netbird_removal_recoveries' AND EXISTS(SELECT 1 FROM uem_netbird_removal_recoveries WHERE id=NEW.id OR (device_id=NEW.device_id AND cancelled_at IS NULL)))
 THEN RAISE EXCEPTION 'NetBird request conflicts with a retained operation'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_registration_admission BEFORE INSERT ON uem_netbird_removal_recoveries
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_admission();
