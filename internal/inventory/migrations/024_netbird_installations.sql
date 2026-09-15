-- Installation requests contain only retained references and public fingerprints.
-- No request is command delivery or permission to bypass package preparation.
CREATE TABLE uem_netbird_installations (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 device_id TEXT NOT NULL CHECK(device_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND device_id<>'00000000-0000-0000-0000-000000000000'),
 tenant_id BIGINT NOT NULL CHECK(tenant_id>0),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 approval_id UUID NOT NULL REFERENCES uem_netbird_packages(id),
 approval_digest TEXT NOT NULL CHECK(approval_digest ~ '^[0-9a-f]{64}$'),
 revision TEXT NOT NULL CHECK(revision ~ '^[0-9a-f]{64}$'),
 journal_revision TEXT NOT NULL CHECK(journal_revision ~ '^[0-9a-f]{64}$'),
 requested_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 cancellation_id UUID UNIQUE CHECK(cancellation_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 cancelled_by TEXT CHECK(octet_length(cancelled_by) BETWEEN 1 AND 255),
 cancelled_at TIMESTAMPTZ,
 CHECK(expires_at>requested_at AND expires_at<=requested_at+interval '10 minutes'),
 CHECK((cancellation_id IS NULL)=(cancelled_by IS NULL) AND (cancellation_id IS NULL)=(cancelled_at IS NULL)),
 CHECK(cancelled_at IS NULL OR cancelled_at>=requested_at)
);
CREATE UNIQUE INDEX uem_netbird_installations_barrier ON uem_netbird_installations(device_id) WHERE cancelled_at IS NULL;
CREATE INDEX uem_netbird_installations_history ON uem_netbird_installations(tenant_id,site_id,device_id,requested_at DESC,id DESC);

CREATE FUNCTION uem_netbird_installation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NetBird installation requests are permanent'; END IF;
 IF (to_jsonb(NEW)-ARRAY['cancellation_id','cancelled_by','cancelled_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['cancellation_id','cancelled_by','cancelled_at'])
  OR (OLD.cancelled_at IS NOT NULL AND NEW IS DISTINCT FROM OLD)
 THEN RAISE EXCEPTION 'NetBird installation intent and cancellation are immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_installation_immutable BEFORE UPDATE OR DELETE ON uem_netbird_installations
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_installation_immutable();

-- Share one UUID namespace and device barrier with connection and registration.
CREATE OR REPLACE FUNCTION uem_netbird_registration_admission() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(684629916,hashtext(NEW.id::text));
 PERFORM pg_advisory_xact_lock(684629914,hashtext(NEW.device_id));
 IF (TG_TABLE_NAME<>'uem_netbird_operations' AND EXISTS(SELECT 1 FROM uem_netbird_operations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))))
  OR (TG_TABLE_NAME<>'uem_netbird_registrations' AND EXISTS(SELECT 1 FROM uem_netbird_registrations WHERE id=NEW.id OR (device_id=NEW.device_id AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))))
  OR (TG_TABLE_NAME<>'uem_netbird_installations' AND EXISTS(SELECT 1 FROM uem_netbird_installations WHERE id=NEW.id OR (device_id=NEW.device_id AND cancelled_at IS NULL)))
 THEN RAISE EXCEPTION 'NetBird request conflicts with a retained operation'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_registration_admission BEFORE INSERT ON uem_netbird_installations
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_registration_admission();

CREATE FUNCTION uem_netbird_installation_approval_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE approved BOOLEAN;
BEGIN
	PERFORM pg_advisory_xact_lock(684629916,hashtext(NEW.id::text));
	PERFORM pg_advisory_xact_lock(684629914,hashtext(NEW.device_id));
 -- Take this lock before reading revocation in a fresh statement. The matching
 -- revocation guard takes UPDATE, including direct database insertions.
 PERFORM 1 FROM uem_netbird_packages WHERE id=NEW.approval_id FOR SHARE;
 SELECT EXISTS(SELECT 1 FROM uem_netbird_packages p WHERE p.id=NEW.approval_id AND p.tenant_id=NEW.tenant_id AND p.digest=NEW.approval_digest
  AND NOT EXISTS(SELECT 1 FROM uem_netbird_package_revocations r WHERE r.approval_id=p.id)) INTO approved;
 IF NOT approved THEN RAISE EXCEPTION 'NetBird installation approval is unavailable'; END IF;
 IF NEW.cancelled_at IS NOT NULL THEN RAISE EXCEPTION 'NetBird installation cannot begin cancelled'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_installation_approval_valid BEFORE INSERT ON uem_netbird_installations
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_installation_approval_valid();

CREATE OR REPLACE FUNCTION uem_netbird_package_revocation_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE actual TEXT;
BEGIN
 SELECT digest INTO actual FROM uem_netbird_packages WHERE id=NEW.approval_id FOR UPDATE;
 IF NOT FOUND OR actual<>NEW.digest THEN RAISE EXCEPTION 'NetBird package revocation does not match the approval'; END IF;
 RETURN NEW;
END $$;
