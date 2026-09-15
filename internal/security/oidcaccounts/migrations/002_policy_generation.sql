CREATE TABLE uem_oidc_policy_generation (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    generation UUID NOT NULL DEFAULT pg_catalog.gen_random_uuid()
);
INSERT INTO uem_oidc_policy_generation(singleton) VALUES(true);

DO $migration$
DECLARE namespace text := current_schema();
BEGIN
 EXECUTE format('CREATE FUNCTION %I.uem_rotate_oidc_policy_generation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,%I AS %L', namespace, namespace, $body$
 BEGIN
  IF TG_OP <> 'UPDATE'
   OR OLD.id IS DISTINCT FROM NEW.id
   OR coalesce(OLD.use_oidc,false) IS DISTINCT FROM coalesce(NEW.use_oidc,false)
   OR coalesce(OLD.oidc_issuer_url,'') IS DISTINCT FROM coalesce(NEW.oidc_issuer_url,'')
   OR coalesce(OLD.oidc_client_id,'') IS DISTINCT FROM coalesce(NEW.oidc_client_id,'')
   OR coalesce(OLD.oidc_provider,'') IS DISTINCT FROM coalesce(NEW.oidc_provider,'')
   OR coalesce(OLD.oidc_role,'') IS DISTINCT FROM coalesce(NEW.oidc_role,'')
   OR coalesce(OLD.oidc_auto_create_account,false) IS DISTINCT FROM coalesce(NEW.oidc_auto_create_account,false)
   OR coalesce(OLD.oidc_auto_approve,false) IS DISTINCT FROM coalesce(NEW.oidc_auto_approve,false)
  THEN
   UPDATE uem_oidc_policy_generation SET generation=pg_catalog.gen_random_uuid() WHERE singleton;
   IF NOT FOUND THEN RAISE EXCEPTION 'OpenID policy generation is unavailable'; END IF;
  END IF;
  RETURN NULL;
 END
 $body$);
 CREATE TRIGGER uem_oidc_policy_generation AFTER INSERT OR UPDATE OR DELETE ON authentications
  FOR EACH ROW EXECUTE FUNCTION uem_rotate_oidc_policy_generation();
 CREATE TRIGGER uem_oidc_policy_truncation AFTER TRUNCATE ON authentications
  FOR EACH STATEMENT EXECUTE FUNCTION uem_rotate_oidc_policy_generation();
END
$migration$;
