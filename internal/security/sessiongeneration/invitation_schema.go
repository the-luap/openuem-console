package sessiongeneration

// Account changes revoke the stored initial-account invitation even when a
// later update restores the previous recipient, status or authentication mode.
const invitationSchema = `
DO $invitation_migration$
DECLARE namespace text := current_schema();
BEGIN
 IF EXISTS(SELECT 1 FROM uem_session_generation_migrations WHERE version=4) THEN
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=pg_catalog.to_regclass('users') AND tgname='uem_account_invitation' AND tgenabled IN ('O','A') AND tgtype=19 AND tgfoid=pg_catalog.to_regprocedure('uem_clear_account_invitation()'))
  THEN RAISE EXCEPTION 'account invitation revocation is incomplete'; END IF;
  RETURN;
 END IF;
 LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE;
 EXECUTE format('CREATE FUNCTION %I.uem_clear_account_invitation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,%I AS %L', namespace, namespace, $body$
 BEGIN
  IF OLD.uid IS DISTINCT FROM NEW.uid
   OR OLD.created IS DISTINCT FROM NEW.created
   OR OLD.email IS DISTINCT FROM NEW.email
   OR OLD.hash IS DISTINCT FROM NEW.hash
   OR coalesce(OLD.passwd,false) IS DISTINCT FROM coalesce(NEW.passwd,false)
   OR coalesce(OLD.openid,false) IS DISTINCT FROM coalesce(NEW.openid,false)
   OR coalesce(OLD.email_verified,false) IS DISTINCT FROM coalesce(NEW.email_verified,false)
   OR OLD.register IS DISTINCT FROM NEW.register
  THEN
   NEW.new_user_token := '';
  END IF;
  RETURN NEW;
 END
 $body$);
 CREATE TRIGGER uem_account_invitation BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION uem_clear_account_invitation();
 INSERT INTO uem_session_generation_migrations(version) VALUES(4);
END
$invitation_migration$;
`
