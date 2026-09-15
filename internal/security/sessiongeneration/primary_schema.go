package sessiongeneration

// Pending primary evidence permits normal required-MFA enrollment confirmation.
// Completed sessions retain their separate, stricter account generation.
const primarySchema = `
DO $primary_migration$
DECLARE namespace text := current_schema();
BEGIN
 IF EXISTS(SELECT 1 FROM uem_session_generation_migrations WHERE version=3) THEN
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=pg_catalog.to_regclass('users') AND tgname='uem_primary_generation' AND tgenabled IN ('O','A') AND tgtype=17 AND tgfoid=pg_catalog.to_regprocedure('uem_rotate_primary_generation()'))
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid=pg_catalog.to_regclass('uem_session_account_generations') AND attname='primary_generation' AND atttypid='uuid'::regtype AND attnotnull AND NOT attisdropped)
  THEN RAISE EXCEPTION 'primary authentication generations are incomplete'; END IF;
  RETURN;
 END IF;
 LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE;
 ALTER TABLE uem_session_account_generations ADD COLUMN IF NOT EXISTS primary_generation uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid();
 EXECUTE format('CREATE FUNCTION %I.uem_rotate_primary_generation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,%I AS %L', namespace, namespace, $body$
 BEGIN
  IF OLD.uid IS DISTINCT FROM NEW.uid
   OR OLD.created IS DISTINCT FROM NEW.created
   OR OLD.hash IS DISTINCT FROM NEW.hash
   OR coalesce(OLD.passwd,false) IS DISTINCT FROM coalesce(NEW.passwd,false)
   OR coalesce(OLD.openid,false) IS DISTINCT FROM coalesce(NEW.openid,false)
   OR coalesce(OLD.use2fa,false) IS DISTINCT FROM coalesce(NEW.use2fa,false)
   OR (coalesce(OLD.totp_secret_confirmed,false) AND NOT coalesce(NEW.totp_secret_confirmed,false))
   OR ((coalesce(OLD.use2fa,false) AND coalesce(OLD.totp_secret_confirmed,false) OR coalesce(NEW.use2fa,false) AND coalesce(NEW.totp_secret_confirmed,false)) AND OLD.totp_secret IS DISTINCT FROM NEW.totp_secret)
   OR (OLD.register IS DISTINCT FROM NEW.register AND NOT(coalesce(OLD.register,'') IN ('users.approved','users.completed','users.certificate_sent') AND coalesce(NEW.register,'') IN ('users.approved','users.completed')))
  THEN
   UPDATE uem_session_account_generations SET primary_generation=pg_catalog.gen_random_uuid() WHERE user_id=NEW.uid;
  END IF;
  RETURN NULL;
 END
 $body$);
 CREATE TRIGGER uem_primary_generation AFTER UPDATE ON users FOR EACH ROW EXECUTE FUNCTION uem_rotate_primary_generation();
 INSERT INTO uem_session_generation_migrations(version) VALUES(3);
END
$primary_migration$;
`
