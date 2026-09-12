package sessiongeneration

// Schema runs inside the caller's migration transaction. Trigger functions bind
// their search path to this application schema, independently of later writers.
// The installation marker preserves UUIDs and avoids replacing active triggers
// during an ordinary repeated startup migration.
const Schema = accountSchema + certificateSchema + primarySchema

const accountSchema = `
SELECT pg_advisory_xact_lock(712036490);
CREATE TABLE IF NOT EXISTS uem_session_account_generations (
 user_id text PRIMARY KEY REFERENCES users(uid) ON UPDATE CASCADE ON DELETE CASCADE,
 generation uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid()
);
CREATE TABLE IF NOT EXISTS uem_session_method_generations (
 method text PRIMARY KEY CHECK(method IN ('password','certificate')),
 generation uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid()
);
CREATE TABLE IF NOT EXISTS uem_session_generation_migrations (version integer PRIMARY KEY);
DO $migration$
DECLARE namespace text := current_schema();
BEGIN
 IF EXISTS(SELECT 1 FROM uem_session_generation_migrations WHERE version=1) THEN
  IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgenabled IN ('O','A') AND (
    tgrelid=pg_catalog.to_regclass('users') AND tgname='uem_account_generation' AND tgtype=21 AND tgfoid=pg_catalog.to_regprocedure('uem_rotate_account_generation()')
    OR tgrelid=pg_catalog.to_regclass('authentications') AND tgname='uem_method_generation' AND tgtype=29 AND tgfoid=pg_catalog.to_regprocedure('uem_rotate_method_generation()')
   )) <> 2
   OR (SELECT count(*) FROM uem_session_method_generations) <> 2
   OR EXISTS(SELECT 1 FROM users u LEFT JOIN uem_session_account_generations g ON g.user_id=u.uid WHERE g.user_id IS NULL)
  THEN RAISE EXCEPTION 'session authentication generations are incomplete'; END IF;
  RETURN;
 END IF;
 INSERT INTO uem_session_account_generations(user_id) SELECT uid FROM users ON CONFLICT DO NOTHING;
 INSERT INTO uem_session_method_generations(method) VALUES('password'),('certificate') ON CONFLICT DO NOTHING;
 EXECUTE format('CREATE FUNCTION %I.uem_rotate_account_generation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,%I AS %L', namespace, namespace, $body$
 BEGIN
  IF TG_OP='INSERT' THEN
   INSERT INTO uem_session_account_generations(user_id) VALUES(NEW.uid);
  ELSIF OLD.uid IS DISTINCT FROM NEW.uid
   OR OLD.created IS DISTINCT FROM NEW.created
   OR OLD.hash IS DISTINCT FROM NEW.hash
   OR coalesce(OLD.passwd,false) IS DISTINCT FROM coalesce(NEW.passwd,false)
   OR coalesce(OLD.openid,false) IS DISTINCT FROM coalesce(NEW.openid,false)
   OR coalesce(OLD.use2fa,false) IS DISTINCT FROM coalesce(NEW.use2fa,false)
   OR coalesce(OLD.totp_secret_confirmed,false) IS DISTINCT FROM coalesce(NEW.totp_secret_confirmed,false)
   OR ((coalesce(OLD.use2fa,false) AND coalesce(OLD.totp_secret_confirmed,false) OR coalesce(NEW.use2fa,false) AND coalesce(NEW.totp_secret_confirmed,false)) AND OLD.totp_secret IS DISTINCT FROM NEW.totp_secret)
   OR (OLD.register IS DISTINCT FROM NEW.register AND NOT(coalesce(OLD.register,'') IN ('users.approved','users.completed','users.certificate_sent') AND coalesce(NEW.register,'') IN ('users.approved','users.completed')))
  THEN
   UPDATE uem_session_account_generations SET generation=pg_catalog.gen_random_uuid() WHERE user_id=NEW.uid;
  END IF;
  RETURN NEW;
 END
 $body$);
 CREATE TRIGGER uem_account_generation AFTER INSERT OR UPDATE ON users FOR EACH ROW EXECUTE FUNCTION uem_rotate_account_generation();
 EXECUTE format('CREATE FUNCTION %I.uem_rotate_method_generation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,%I AS %L', namespace, namespace, $body$
 BEGIN
  IF TG_OP='INSERT' OR TG_OP='DELETE' THEN
   UPDATE uem_session_method_generations SET generation=pg_catalog.gen_random_uuid();
  ELSE
   IF coalesce(OLD.use_passwd,false) IS DISTINCT FROM coalesce(NEW.use_passwd,false) THEN
    UPDATE uem_session_method_generations SET generation=pg_catalog.gen_random_uuid() WHERE method='password';
   END IF;
   IF coalesce(OLD.use_certificates,false) IS DISTINCT FROM coalesce(NEW.use_certificates,false) THEN
    UPDATE uem_session_method_generations SET generation=pg_catalog.gen_random_uuid() WHERE method='certificate';
   END IF;
  END IF;
  RETURN NULL;
 END
 $body$);
 CREATE TRIGGER uem_method_generation AFTER INSERT OR UPDATE OR DELETE ON authentications FOR EACH ROW EXECUTE FUNCTION uem_rotate_method_generation();
 INSERT INTO uem_session_generation_migrations(version) VALUES(1);
END
$migration$;
`
