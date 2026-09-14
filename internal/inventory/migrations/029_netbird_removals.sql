-- Retain reviewed native state separately from installation sources and provider
-- peers. These records authorize no native delivery by themselves.
CREATE TABLE uem_netbird_removals (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 device_id TEXT NOT NULL CHECK(device_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND device_id<>'00000000-0000-0000-0000-000000000000'),
 tenant_id BIGINT NOT NULL CHECK(tenant_id>0),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 revision TEXT NOT NULL CHECK(revision ~ '^[0-9a-f]{64}$'),
 journal_revision TEXT NOT NULL CHECK(journal_revision ~ '^[0-9a-f]{64}$'),
 descriptor_digest TEXT NOT NULL CHECK(descriptor_digest ~ '^[0-9a-f]{64}$'),
 descriptor JSONB NOT NULL CHECK(octet_length(descriptor::text)<=4096),
 requested_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 cancellation_id UUID UNIQUE CHECK(cancellation_id<>'00000000-0000-0000-0000-000000000000'::uuid AND cancellation_id<>id),
 cancelled_by TEXT CHECK(octet_length(cancelled_by) BETWEEN 1 AND 255),
 cancelled_at TIMESTAMPTZ,
 CHECK(expires_at>requested_at AND expires_at<=requested_at+interval '10 minutes'),
 CHECK((cancellation_id IS NULL)=(cancelled_by IS NULL) AND (cancellation_id IS NULL)=(cancelled_at IS NULL)),
 CHECK(cancelled_at IS NULL OR cancelled_at>=requested_at),
 CHECK(coalesce(descriptor=jsonb_build_object('schema',1,'platform',descriptor->'platform','architecture',descriptor->'architecture',
  'format',descriptor->'format','package_id',descriptor->'package_id','version',descriptor->'version','state_digest',descriptor->'state_digest')
  AND descriptor->>'schema'='1'
  AND jsonb_typeof(descriptor->'platform')='string' AND jsonb_typeof(descriptor->'architecture')='string'
  AND jsonb_typeof(descriptor->'format')='string' AND jsonb_typeof(descriptor->'package_id')='string'
  AND jsonb_typeof(descriptor->'version')='string' AND octet_length(descriptor->>'version') BETWEEN 1 AND 128
  AND descriptor->>'version' ~ '^[0-9A-Za-z][0-9A-Za-z.+:~_-]*$'
  AND jsonb_typeof(descriptor->'state_digest')='string' AND descriptor->>'state_digest' ~ '^[0-9a-f]{64}$'
  AND ((descriptor->>'platform'='macos' AND descriptor->>'format'='pkg' AND descriptor->>'package_id'='io.netbird.client' AND descriptor->>'architecture' IN ('arm64','amd64'))
   OR (descriptor->>'platform'='linux' AND descriptor->>'format' IN ('deb','rpm') AND descriptor->>'package_id'='netbird' AND descriptor->>'architecture' IN ('arm64','amd64','386'))),false))
);
CREATE UNIQUE INDEX uem_netbird_removals_barrier ON uem_netbird_removals(device_id) WHERE cancelled_at IS NULL;
CREATE INDEX uem_netbird_removals_history ON uem_netbird_removals(tenant_id,site_id,device_id,requested_at DESC,id DESC);

CREATE FUNCTION uem_netbird_removal_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NetBird removal requests are permanent'; END IF;
 IF (to_jsonb(NEW)-ARRAY['cancellation_id','cancelled_by','cancelled_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['cancellation_id','cancelled_by','cancelled_at'])
  OR (OLD.cancelled_at IS NOT NULL AND NEW IS DISTINCT FROM OLD)
 THEN RAISE EXCEPTION 'NetBird removal intent and cancellation are immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removals
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_immutable();

CREATE FUNCTION uem_netbird_removal_initial() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.cancelled_at IS NOT NULL THEN RAISE EXCEPTION 'NetBird removal cannot begin cancelled'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_initial BEFORE INSERT ON uem_netbird_removals
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_initial();

-- Share both the permanent UUID namespace and unresolved device exclusion with
-- connection, registration and installation, including direct database writers.
CREATE OR REPLACE FUNCTION uem_netbird_registration_admission() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(684629916,hashtext(NEW.id::text));
 PERFORM pg_advisory_xact_lock(684629914,hashtext(NEW.device_id));
 IF (TG_TABLE_NAME<>'uem_netbird_operations' AND EXISTS(SELECT 1 FROM uem_netbird_operations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))))
  OR (TG_TABLE_NAME<>'uem_netbird_registrations' AND EXISTS(SELECT 1 FROM uem_netbird_registrations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))))
  OR (TG_TABLE_NAME<>'uem_netbird_installations' AND EXISTS(SELECT 1 FROM uem_netbird_installations WHERE id=NEW.id OR (device_id=NEW.device_id AND cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL)))
  OR (TG_TABLE_NAME<>'uem_netbird_removals' AND EXISTS(SELECT 1 FROM uem_netbird_removals WHERE id=NEW.id OR (device_id=NEW.device_id AND cancelled_at IS NULL)))
 THEN RAISE EXCEPTION 'NetBird request conflicts with a retained operation'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_registration_admission BEFORE INSERT ON uem_netbird_removals
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_admission();
