-- Existing field names were globally unique. Remove only that exact invariant;
-- preserve unrelated native and application indexes during the scoped upgrade.
DO $scope$
DECLARE item record;
DECLARE name_column smallint;
BEGIN
 SELECT attnum INTO name_column FROM pg_attribute WHERE attrelid='org_metadata'::regclass AND attname='name' AND NOT attisdropped;
 FOR item IN SELECT conname FROM pg_constraint WHERE conrelid='org_metadata'::regclass AND contype='u' AND conkey=ARRAY[name_column] LOOP
  EXECUTE format('ALTER TABLE org_metadata DROP CONSTRAINT %I',item.conname);
 END LOOP;
 FOR item IN SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
  WHERE i.indrelid='org_metadata'::regclass AND i.indisunique AND NOT i.indisprimary
   AND i.indnkeyatts=1 AND i.indkey[0]=name_column AND i.indpred IS NULL AND i.indexprs IS NULL LOOP
  EXECUTE format('DROP INDEX %I',item.relname);
 END LOOP;
END
$scope$;
CREATE UNIQUE INDEX IF NOT EXISTS uem_metadata_field_name_tenant ON org_metadata(tenant_metadata,name);

ALTER TABLE org_metadata ADD COLUMN uem_revision uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid();
DO $migration$
DECLARE namespace text := current_schema();
BEGIN
 EXECUTE format('CREATE FUNCTION %I.uem_metadata_field_revision() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,%I AS %L',namespace,namespace,$body$
 BEGIN
  IF TG_OP='INSERT' THEN
   NEW.uem_revision=pg_catalog.gen_random_uuid();
  ELSIF ROW(NEW.name,NEW.description,NEW.tenant_metadata) IS DISTINCT FROM ROW(OLD.name,OLD.description,OLD.tenant_metadata) THEN
   NEW.uem_revision=pg_catalog.gen_random_uuid();
  ELSIF NEW.uem_revision IS DISTINCT FROM OLD.uem_revision THEN
   RAISE EXCEPTION 'metadata field revision cannot be replaced';
  END IF;
  RETURN NEW;
 END
 $body$);
END
$migration$;
CREATE TRIGGER uem_metadata_field_revision BEFORE INSERT OR UPDATE ON org_metadata
 FOR EACH ROW EXECUTE FUNCTION uem_metadata_field_revision();

-- Keep absence revisions after a value, field or device has been deleted.
CREATE TABLE uem_metadata_value_revisions (
 device_id text NOT NULL CHECK(length(device_id) BETWEEN 1 AND 255),
 field_id bigint NOT NULL CHECK(field_id>0),
 changed boolean NOT NULL DEFAULT false,
 revision uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
 PRIMARY KEY(device_id,field_id)
);
CREATE FUNCTION uem_metadata_value_revision_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND (pg_trigger_depth()=1 OR ROW(NEW.device_id,NEW.field_id) IS DISTINCT FROM ROW(OLD.device_id,OLD.field_id))) THEN
  RAISE EXCEPTION 'metadata value revision cannot be replaced or deleted';
 END IF;
 NEW.revision=pg_catalog.gen_random_uuid();
 RETURN NEW;
END $$;
CREATE TRIGGER uem_metadata_value_revision_guard BEFORE INSERT OR UPDATE OR DELETE ON uem_metadata_value_revisions
 FOR EACH ROW EXECUTE FUNCTION uem_metadata_value_revision_guard();
INSERT INTO uem_metadata_value_revisions(device_id,field_id,changed)
 SELECT agent_metadata,org_metadata_metadata,true FROM metadata;

DO $migration$
DECLARE namespace text := current_schema();
BEGIN
 EXECUTE format('CREATE FUNCTION %I.uem_metadata_value_revision() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,%I AS %L',namespace,namespace,$body$
 BEGIN
  IF TG_OP='UPDATE' AND ROW(NEW.value,NEW.agent_metadata,NEW.org_metadata_metadata) IS NOT DISTINCT FROM ROW(OLD.value,OLD.agent_metadata,OLD.org_metadata_metadata) THEN
   RETURN NEW;
  END IF;
  IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND ROW(OLD.agent_metadata,OLD.org_metadata_metadata) IS DISTINCT FROM ROW(NEW.agent_metadata,NEW.org_metadata_metadata)) THEN
   INSERT INTO uem_metadata_value_revisions(device_id,field_id,changed) VALUES(OLD.agent_metadata,OLD.org_metadata_metadata,true)
    ON CONFLICT(device_id,field_id) DO UPDATE SET revision=pg_catalog.gen_random_uuid(),changed=true;
  END IF;
  IF TG_OP<>'DELETE' THEN
   INSERT INTO uem_metadata_value_revisions(device_id,field_id,changed) VALUES(NEW.agent_metadata,NEW.org_metadata_metadata,true)
    ON CONFLICT(device_id,field_id) DO UPDATE SET revision=pg_catalog.gen_random_uuid(),changed=true;
  END IF;
  RETURN NULL;
 END
 $body$);
END
$migration$;
CREATE TRIGGER uem_metadata_value_revision AFTER INSERT OR UPDATE OR DELETE ON metadata
 FOR EACH ROW EXECUTE FUNCTION uem_metadata_value_revision();

CREATE TABLE uem_metadata_field_deletions (
 id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
 tenant_id bigint NOT NULL CHECK(tenant_id>0),
 field_id bigint NOT NULL CHECK(field_id>0),
 field_revision uuid NOT NULL,
 actor text NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 name text NOT NULL,
 description text NOT NULL,
 value_count bigint NOT NULL CHECK(value_count>=0),
 source_hash bytea NOT NULL CHECK(octet_length(source_hash)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '10 minutes',
 completed_at timestamptz,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '15 minutes'),
 CHECK(completed_at IS NULL OR (completed_at>=created_at AND completed_at<=expires_at))
);
CREATE INDEX uem_metadata_field_deletions_scope ON uem_metadata_field_deletions(tenant_id,field_id,created_at DESC);
CREATE FUNCTION uem_metadata_field_deletion_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'metadata deletion evidence cannot be deleted'; END IF;
 IF OLD.completed_at IS NOT NULL OR NEW.completed_at IS NULL OR (to_jsonb(NEW)-'completed_at') IS DISTINCT FROM (to_jsonb(OLD)-'completed_at') THEN
  RAISE EXCEPTION 'metadata deletion review cannot be replaced';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_metadata_field_deletion_guard BEFORE UPDATE OR DELETE ON uem_metadata_field_deletions
 FOR EACH ROW EXECUTE FUNCTION uem_metadata_field_deletion_guard();
