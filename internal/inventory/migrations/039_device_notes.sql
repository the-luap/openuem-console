-- Preserve the canonical Ent notes column and detect changes by legacy writers.
ALTER TABLE agents ADD COLUMN uem_notes_revision uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid();
DO $migration$
DECLARE namespace text := current_schema();
BEGIN
 EXECUTE format('CREATE FUNCTION %I.uem_device_notes_revision() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,%I AS %L',namespace,namespace,$body$
 BEGIN
  IF TG_OP='INSERT' THEN
   NEW.uem_notes_revision=pg_catalog.gen_random_uuid();
  ELSIF NEW.notes IS DISTINCT FROM OLD.notes THEN
   NEW.uem_notes_revision=pg_catalog.gen_random_uuid();
  ELSIF NEW.uem_notes_revision IS DISTINCT FROM OLD.uem_notes_revision THEN
   RAISE EXCEPTION 'device notes revision cannot be replaced';
  END IF;
  RETURN NEW;
 END
 $body$);
END
$migration$;
CREATE TRIGGER uem_device_notes_revision BEFORE INSERT OR UPDATE ON agents
 FOR EACH ROW EXECUTE FUNCTION uem_device_notes_revision();
