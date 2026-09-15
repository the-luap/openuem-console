-- Keep administrative labels in the canonical agent fields, with a shared
-- revision that also changes when an older writer edits any of the fields.
ALTER TABLE agents ADD COLUMN uem_details_revision uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid();
DO $migration$
DECLARE namespace text := current_schema();
BEGIN
 EXECUTE format('CREATE FUNCTION %I.uem_device_details_revision() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,%I AS %L',namespace,namespace,$body$
 BEGIN
  IF TG_OP='INSERT' THEN
   NEW.uem_details_revision=pg_catalog.gen_random_uuid();
  ELSIF ROW(NEW.nickname,NEW.description,NEW.endpoint_type) IS DISTINCT FROM ROW(OLD.nickname,OLD.description,OLD.endpoint_type) THEN
   NEW.uem_details_revision=pg_catalog.gen_random_uuid();
  ELSIF NEW.uem_details_revision IS DISTINCT FROM OLD.uem_details_revision THEN
   RAISE EXCEPTION 'device details revision cannot be replaced';
  END IF;
  RETURN NEW;
 END
 $body$);
END
$migration$;
CREATE TRIGGER uem_device_details_revision BEFORE INSERT OR UPDATE ON agents
 FOR EACH ROW EXECUTE FUNCTION uem_device_details_revision();
