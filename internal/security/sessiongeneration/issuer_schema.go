package sessiongeneration

// The public console client issuer is shared by authentication and session
// verification. Its generation cannot be restored by copying earlier CA bytes.
const issuerSchema = `
DO $migration$
DECLARE namespace text := current_schema();
BEGIN
 IF EXISTS(SELECT 1 FROM uem_session_generation_migrations WHERE version=5) THEN
  IF (SELECT count(*) FROM uem_console_certificate_issuer WHERE singleton AND generation IS NOT NULL)<>1
   OR (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid=pg_catalog.to_regclass('uem_console_certificate_issuer') AND tgenabled IN ('O','A') AND tgfoid=pg_catalog.to_regprocedure('uem_guard_console_certificate_issuer()') AND ((tgname='uem_console_issuer_generation' AND tgtype=27) OR (tgname='uem_console_issuer_truncation' AND tgtype=34)))<>2
  THEN RAISE EXCEPTION 'console certificate issuer protection is incomplete'; END IF;
  RETURN;
 END IF;
 CREATE TABLE uem_console_certificate_issuer (
  singleton boolean PRIMARY KEY CHECK(singleton),
  generation uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
  certificate bytea CHECK(certificate IS NULL OR octet_length(certificate) BETWEEN 1 AND 16384)
 );
 INSERT INTO uem_console_certificate_issuer(singleton) VALUES(true);
 EXECUTE format('CREATE FUNCTION %I.uem_guard_console_certificate_issuer() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,%I AS %L', namespace, namespace, $body$
 BEGIN
  IF TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'console certificate issuer state must be retained'; END IF;
  IF NEW.singleton IS DISTINCT FROM OLD.singleton THEN RAISE EXCEPTION 'console certificate issuer identity is immutable'; END IF;
  IF NEW.certificate IS DISTINCT FROM OLD.certificate THEN
   NEW.generation=pg_catalog.gen_random_uuid();
  ELSIF NEW.generation IS DISTINCT FROM OLD.generation THEN
   RAISE EXCEPTION 'console certificate issuer generation cannot be replaced';
  END IF;
  RETURN NEW;
 END
 $body$);
 CREATE TRIGGER uem_console_issuer_generation BEFORE UPDATE OR DELETE ON uem_console_certificate_issuer
  FOR EACH ROW EXECUTE FUNCTION uem_guard_console_certificate_issuer();
 CREATE TRIGGER uem_console_issuer_truncation BEFORE TRUNCATE ON uem_console_certificate_issuer
  FOR EACH STATEMENT EXECUTE FUNCTION uem_guard_console_certificate_issuer();
 INSERT INTO uem_session_generation_migrations(version) VALUES(5);
END
$migration$;
`
