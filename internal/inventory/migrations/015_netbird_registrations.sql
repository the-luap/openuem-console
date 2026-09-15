CREATE TABLE uem_netbird_registrations (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 device_id TEXT NOT NULL CHECK(device_id ~ '^[A-Za-z0-9_-]{1,255}$'),
 tenant_id BIGINT NOT NULL CHECK(tenant_id>0),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 individual BOOLEAN NOT NULL,
 revision TEXT NOT NULL CHECK(revision ~ '^[0-9a-f]{64}$'),
 groups JSONB NOT NULL CHECK(jsonb_typeof(groups)='array' AND jsonb_array_length(groups)<=100 AND octet_length(groups::text)<=32768),
 extra_dns BOOLEAN NOT NULL,
 snapshot TEXT NOT NULL CHECK(snapshot LIKE 'openuem:netbird-registration:v1:%' AND octet_length(snapshot)<=45000),
 status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','completed','stopped','unconfirmed')),
 reason TEXT NOT NULL DEFAULT '' CHECK(reason IN ('','expired','mode_changed','not_authorized','source_changed','cancelled','registration_unconfirmed','recovered_without_delivery')),
 requested_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 finished_at TIMESTAMPTZ,
 CHECK(expires_at>requested_at AND expires_at<=requested_at+interval '2 minutes'),
 CHECK((status='queued')=(finished_at IS NULL)),
 CHECK((status IN ('queued','completed'))=(reason='')),
 CHECK((status='unconfirmed')=(reason='registration_unconfirmed'))
);
CREATE UNIQUE INDEX uem_netbird_registrations_barrier ON uem_netbird_registrations(device_id) WHERE status IN ('queued','unconfirmed');
CREATE INDEX uem_netbird_registrations_due ON uem_netbird_registrations(requested_at,id) WHERE status='queued';
CREATE INDEX uem_netbird_registrations_history ON uem_netbird_registrations(tenant_id,site_id,device_id,requested_at DESC,id DESC);

-- These records commit independently while dispatch holds the request lock.
-- No foreign key may wait for that outer transaction.
CREATE TABLE uem_netbird_registration_attempts (
 request_id UUID NOT NULL,
 stage TEXT NOT NULL CHECK(stage IN ('create','deliver','delete')),
 revision TEXT NOT NULL CHECK(revision ~ '^[0-9a-f]{64}$'),
 digest TEXT NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(request_id,stage)
);
CREATE TABLE uem_netbird_registration_evidence (
 request_id UUID NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('key','delivered','absent')),
 data JSONB NOT NULL CHECK(jsonb_typeof(data)='object' AND octet_length(data::text)<=32768),
 secret TEXT NOT NULL DEFAULT '' CHECK(octet_length(secret)<=45000),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(request_id,kind),
 CHECK((kind='key')=(secret<>'')),
 CHECK(secret='' OR secret LIKE 'openuem:netbird-registration:v1:%')
);

CREATE FUNCTION uem_netbird_registration_attempt_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird registration attempts are permanent'; END $$;
CREATE TRIGGER uem_netbird_registration_attempt_immutable BEFORE UPDATE OR DELETE ON uem_netbird_registration_attempts FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_attempt_immutable();
CREATE FUNCTION uem_netbird_registration_evidence_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird registration evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_registration_evidence_immutable BEFORE UPDATE OR DELETE ON uem_netbird_registration_evidence FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_evidence_immutable();

CREATE FUNCTION uem_netbird_registration_attempt_valid() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM uem_netbird_registrations WHERE id=NEW.request_id AND revision=NEW.revision AND status='queued') THEN RAISE EXCEPTION 'NetBird registration request is missing'; END IF;
 IF NEW.stage<>'create' AND NOT EXISTS(SELECT 1 FROM uem_netbird_registration_evidence WHERE request_id=NEW.request_id AND kind='key') THEN RAISE EXCEPTION 'NetBird registration key evidence is missing'; END IF;
 IF NEW.stage='deliver' AND EXISTS(SELECT 1 FROM uem_netbird_registration_attempts WHERE request_id=NEW.request_id AND stage='delete') THEN RAISE EXCEPTION 'NetBird registration key is being removed'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_registration_attempt_valid BEFORE INSERT ON uem_netbird_registration_attempts FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_attempt_valid();

CREATE FUNCTION uem_netbird_registration_evidence_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_registrations%ROWTYPE; a uem_netbird_registration_attempts%ROWTYPE; k JSONB;
BEGIN
 SELECT * INTO r FROM uem_netbird_registrations WHERE id=NEW.request_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'NetBird registration request is missing'; END IF;
 SELECT * INTO a FROM uem_netbird_registration_attempts WHERE request_id=r.id AND revision=r.revision AND stage=CASE NEW.kind WHEN 'key' THEN 'create' WHEN 'delivered' THEN 'deliver' ELSE 'delete' END;
 IF NOT FOUND THEN RAISE EXCEPTION 'NetBird registration attempt is missing'; END IF;
 IF NEW.kind='key' THEN
  k:=NEW.data;
  IF k IS DISTINCT FROM jsonb_build_object('ID',k->'ID','Name','OpenUEM registration '||r.id::text,'Type','one-off','ExpiresAt',k->'ExpiresAt','Groups',r.groups,'UsageLimit',1,'UsedTimes',0,'ExtraDNS',r.extra_dns,'Ephemeral',false,'Valid',true,'Revoked',false)
   OR NOT coalesce(k->>'ID' ~ '^[A-Za-z0-9_-]{1,128}$',false)
   OR k->>'Name' IS DISTINCT FROM 'OpenUEM registration '||r.id::text
   OR k->>'Type' IS DISTINCT FROM 'one-off' OR k->'UsageLimit' IS DISTINCT FROM '1'::jsonb
   OR k->'UsedTimes' IS DISTINCT FROM '0'::jsonb OR k->'Valid' IS DISTINCT FROM 'true'::jsonb
   OR k->'Revoked' IS DISTINCT FROM 'false'::jsonb OR k->'Ephemeral' IS DISTINCT FROM 'false'::jsonb
   OR k->'Groups' IS DISTINCT FROM r.groups OR k->'ExtraDNS' IS DISTINCT FROM to_jsonb(r.extra_dns)
   OR jsonb_typeof(k->'ExpiresAt') IS DISTINCT FROM 'string'
   OR k ? 'Secret' THEN RAISE EXCEPTION 'NetBird registration key policy does not match'; END IF;
 ELSIF NEW.kind='delivered' THEN
  IF NEW.data IS DISTINCT FROM jsonb_build_object('request_id',r.id::text,'device_id',r.device_id,'revision',r.revision,'operation','register','success',true,'command_hash',a.digest) THEN RAISE EXCEPTION 'NetBird registration delivery does not match'; END IF;
 ELSE
  SELECT data INTO k FROM uem_netbird_registration_evidence WHERE request_id=r.id AND kind='key';
  IF NOT FOUND OR NEW.data IS DISTINCT FROM jsonb_build_object('key_id',k->>'ID','absent',true) THEN RAISE EXCEPTION 'NetBird registration cleanup does not match'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_registration_evidence_valid BEFORE INSERT ON uem_netbird_registration_evidence FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_evidence_valid();

CREATE FUNCTION uem_netbird_registration_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE created BOOLEAN; delivered BOOLEAN; cleaned BOOLEAN;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NetBird registration receipts are permanent'; END IF;
 IF (to_jsonb(NEW)-ARRAY['status','reason','finished_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','reason','finished_at']) THEN RAISE EXCEPTION 'NetBird registration identity is immutable'; END IF;
 IF OLD.status<>'queued' AND NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'NetBird registration outcome is immutable'; END IF;
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
CREATE TRIGGER uem_netbird_registration_immutable BEFORE UPDATE OR DELETE ON uem_netbird_registrations FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_immutable();

-- Serialize both request families, including callers using another replica.
CREATE FUNCTION uem_netbird_registration_admission() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(684629916,hashtext(NEW.id::text));
 PERFORM pg_advisory_xact_lock(684629914,hashtext(NEW.device_id));
 IF (TG_TABLE_NAME='uem_netbird_registrations' AND EXISTS(SELECT 1 FROM uem_netbird_operations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))))
  OR (TG_TABLE_NAME='uem_netbird_operations' AND EXISTS(SELECT 1 FROM uem_netbird_registrations WHERE id=NEW.id OR (device_id=NEW.device_id AND status IN ('queued','unconfirmed')))) THEN RAISE EXCEPTION 'NetBird request conflicts with a recorded registration'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_registration_admission BEFORE INSERT ON uem_netbird_registrations FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_admission();
CREATE TRIGGER uem_netbird_registration_admission BEFORE INSERT ON uem_netbird_operations FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_admission();
