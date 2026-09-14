-- Preparation authorizes one bounded download/inspection, never installation.
-- Exact wire identity is reconstructible from the immutable request/approval;
-- private package sources remain solely in the encrypted approval envelope.
CREATE TABLE uem_netbird_preparations (
 request_id UUID PRIMARY KEY REFERENCES uem_netbird_installations(id),
 wire_version INTEGER NOT NULL CHECK(wire_version=1),
 certificate_hash TEXT NOT NULL CHECK(certificate_hash ~ '^[0-9a-f]{64}$'),
 request_hash TEXT NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
 issued_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '10 minutes')
);
CREATE TABLE uem_netbird_preparation_results (
 request_id UUID PRIMARY KEY REFERENCES uem_netbird_preparations(request_id),
 outcome TEXT NOT NULL CHECK(outcome IN ('prepared','blocked','conflict','unavailable','unconfirmed')),
 response JSONB,
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK((outcome='unconfirmed')=(response IS NULL))
);
CREATE FUNCTION uem_netbird_preparation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'NetBird preparation attempts and results are permanent';
END $$;
CREATE TRIGGER uem_netbird_preparation_immutable BEFORE UPDATE OR DELETE ON uem_netbird_preparations
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_preparation_immutable();
CREATE FUNCTION uem_netbird_preparation_result_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'NetBird preparation results are permanent';
END $$;
CREATE TRIGGER uem_netbird_preparation_result_immutable BEFORE UPDATE OR DELETE ON uem_netbird_preparation_results
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_preparation_result_immutable();

CREATE FUNCTION uem_netbird_preparation_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_installations%ROWTYPE; current_identity BOOLEAN; approved BOOLEAN;
BEGIN
 SELECT * INTO r FROM uem_netbird_installations WHERE id=NEW.request_id FOR UPDATE;
 IF NOT FOUND OR r.cancelled_at IS NOT NULL OR clock_timestamp()>=r.expires_at
  OR NEW.issued_at<r.requested_at OR NEW.expires_at>r.expires_at
  OR NEW.issued_at>clock_timestamp()+interval '30 seconds' OR NEW.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'NetBird preparation request is unavailable'; END IF;
 PERFORM 1 FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id
  WHERE i.id=r.device_id::uuid FOR SHARE OF i,q;
 SELECT EXISTS(SELECT 1 FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id
  WHERE i.id=r.device_id::uuid AND i.tenant_id=r.tenant_id AND i.site_id=r.site_id
   AND i.certificate_hash=NEW.certificate_hash AND i.certificate_expires_at>=NEW.expires_at
   AND i.revoked_at IS NULL AND q.desired_active AND q.revision=q.completed_revision) INTO current_identity;
 PERFORM 1 FROM uem_netbird_packages WHERE id=r.approval_id FOR SHARE;
 SELECT EXISTS(SELECT 1 FROM uem_netbird_packages p WHERE p.id=r.approval_id AND p.tenant_id=r.tenant_id AND p.digest=r.approval_digest
  AND NOT EXISTS(SELECT 1 FROM uem_netbird_package_revocations v WHERE v.approval_id=p.id)) INTO approved;
 IF NOT current_identity OR NOT approved THEN RAISE EXCEPTION 'NetBird preparation authority changed'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_preparation_valid BEFORE INSERT ON uem_netbird_preparations
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_preparation_valid();

CREATE FUNCTION uem_netbird_preparation_result_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_installations%ROWTYPE; p uem_netbird_preparations%ROWTYPE; expected JSONB;
BEGIN
 -- Cancellation may finish while a preparation is in flight. Its later result
 -- remains historical evidence, and cannot undo cancellation or authorize install.
 SELECT * INTO r FROM uem_netbird_installations WHERE id=NEW.request_id FOR UPDATE;
 SELECT * INTO p FROM uem_netbird_preparations WHERE request_id=NEW.request_id;
 IF NOT FOUND OR NEW.recorded_at<p.issued_at OR NEW.recorded_at>clock_timestamp()+interval '30 seconds'
  OR (NEW.outcome='prepared' AND (NEW.recorded_at>=p.expires_at OR clock_timestamp()>=p.expires_at))
 THEN RAISE EXCEPTION 'NetBird preparation result has no current attempt'; END IF;
 IF NEW.outcome<>'unconfirmed' THEN
  expected=jsonb_build_object('version',p.wire_version,'device_id',r.device_id,'tenant_id',r.tenant_id,'site_id',r.site_id,
   'individual',true,'certificate_hash',p.certificate_hash,'request_id',r.id::text,'request_hash',p.request_hash,'outcome',NEW.outcome);
  IF NEW.response IS DISTINCT FROM expected THEN RAISE EXCEPTION 'NetBird preparation result does not match its attempt'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_preparation_result_valid BEFORE INSERT ON uem_netbird_preparation_results
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_preparation_result_valid();
