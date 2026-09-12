package sessiongeneration

// Certificate generations preserve retirement even when a registry mutation is
// subsequently reversed. The caller already holds the shared migration lock.
const certificateSchema = `
CREATE TABLE IF NOT EXISTS uem_session_certificate_generations (
 serial bigint PRIMARY KEY REFERENCES certificates(serial) ON UPDATE CASCADE ON DELETE CASCADE,
 generation uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid()
);
DO $certificate_migration$
DECLARE namespace text := current_schema();
BEGIN
 IF EXISTS(SELECT 1 FROM uem_session_generation_migrations WHERE version=2) THEN
  IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgenabled IN ('O','A') AND (
    tgrelid=pg_catalog.to_regclass('certificates') AND tgname='uem_certificate_generation' AND tgtype=21 AND tgfoid=pg_catalog.to_regprocedure('uem_rotate_certificate_generation()')
    OR tgrelid=pg_catalog.to_regclass('revocations') AND tgname='uem_revocation_generation' AND tgtype=29 AND tgfoid=pg_catalog.to_regprocedure('uem_rotate_revocation_generation()')
   )) <> 2
   OR EXISTS(SELECT 1 FROM certificates c LEFT JOIN uem_session_certificate_generations g ON g.serial=c.serial WHERE g.serial IS NULL)
  THEN RAISE EXCEPTION 'session certificate generations are incomplete'; END IF;
  RETURN;
 END IF;
 LOCK TABLE certificates,revocations IN SHARE ROW EXCLUSIVE MODE;
 INSERT INTO uem_session_certificate_generations(serial) SELECT serial FROM certificates ON CONFLICT DO NOTHING;
 EXECUTE format('CREATE FUNCTION %I.uem_rotate_certificate_generation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,%I AS %L', namespace, namespace, $body$
 BEGIN
  IF TG_OP='INSERT' THEN
   INSERT INTO uem_session_certificate_generations(serial) VALUES(NEW.serial);
  ELSIF OLD.serial IS DISTINCT FROM NEW.serial OR OLD.uid IS DISTINCT FROM NEW.uid
   OR OLD.type IS DISTINCT FROM NEW.type OR OLD.expiry IS DISTINCT FROM NEW.expiry
  THEN
   UPDATE uem_session_certificate_generations SET generation=pg_catalog.gen_random_uuid() WHERE serial=NEW.serial;
  END IF;
  RETURN NULL;
 END
 $body$);
 CREATE TRIGGER uem_certificate_generation AFTER INSERT OR UPDATE ON certificates FOR EACH ROW EXECUTE FUNCTION uem_rotate_certificate_generation();
 EXECUTE format('CREATE FUNCTION %I.uem_rotate_revocation_generation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,%I AS %L', namespace, namespace, $body$
 BEGIN
  IF TG_OP <> 'INSERT' THEN
   UPDATE uem_session_certificate_generations SET generation=pg_catalog.gen_random_uuid() WHERE serial=OLD.serial;
  END IF;
  IF TG_OP <> 'DELETE' THEN
   UPDATE uem_session_certificate_generations SET generation=pg_catalog.gen_random_uuid() WHERE serial=NEW.serial;
  END IF;
  RETURN NULL;
 END
 $body$);
 CREATE TRIGGER uem_revocation_generation AFTER INSERT OR UPDATE OR DELETE ON revocations FOR EACH ROW EXECUTE FUNCTION uem_rotate_revocation_generation();
 INSERT INTO uem_session_generation_migrations(version) VALUES(2);
END
$certificate_migration$;
`
