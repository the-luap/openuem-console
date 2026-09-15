-- Legacy Ent writers retain their API and participate in revision checks.
ALTER TABLE tags ADD COLUMN uem_revision uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid();
DO $migration$
DECLARE namespace text := current_schema();
BEGIN
 EXECUTE format('CREATE FUNCTION %I.uem_tag_revision() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,%I AS %L',namespace,namespace,$body$
 BEGIN
  IF TG_OP='INSERT' THEN
   NEW.uem_revision=pg_catalog.gen_random_uuid();
  ELSIF (NEW.id,NEW.tag,NEW.description,NEW.color,NEW.tenant_tags,NEW.tag_children,NEW.task_tags)
     IS DISTINCT FROM (OLD.id,OLD.tag,OLD.description,OLD.color,OLD.tenant_tags,OLD.tag_children,OLD.task_tags) THEN
   NEW.uem_revision=pg_catalog.gen_random_uuid();
  ELSIF NEW.uem_revision IS DISTINCT FROM OLD.uem_revision THEN
   RAISE EXCEPTION 'tag revision cannot be replaced';
  END IF;
  RETURN NEW;
 END
 $body$);
END
$migration$;
CREATE TRIGGER uem_tag_revision BEFORE INSERT OR UPDATE ON tags
 FOR EACH ROW EXECUTE FUNCTION uem_tag_revision();
CREATE INDEX uem_tags_tenant_page ON tags(tenant_tags,id);
