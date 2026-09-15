-- A reviewed transfer keeps its original authority and impact after completion.
CREATE TABLE uem_device_assignment_reviews (
 id UUID PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
 device_id TEXT NOT NULL CHECK(length(device_id) BETWEEN 1 AND 255),
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 source_tenant BIGINT NOT NULL CHECK(source_tenant>0),
 source_site BIGINT NOT NULL CHECK(source_site>0),
 target_tenant BIGINT NOT NULL CHECK(target_tenant>0),
 target_site BIGINT NOT NULL CHECK(target_site>0 AND target_site<>source_site),
 device_name TEXT NOT NULL,
 source_organization TEXT NOT NULL,
 source_location TEXT NOT NULL,
 target_organization TEXT NOT NULL,
 target_location TEXT NOT NULL,
 tag_count BIGINT NOT NULL CHECK(tag_count>=0),
 metadata_count BIGINT NOT NULL CHECK(metadata_count>=0),
 source_hash BYTEA NOT NULL CHECK(octet_length(source_hash)=32),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()+interval '10 minutes',
 completed_at TIMESTAMPTZ,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '15 minutes'),
 CHECK(completed_at IS NULL OR (completed_at>=created_at AND completed_at<=expires_at))
);
CREATE INDEX uem_device_assignment_history ON uem_device_assignment_reviews(device_id,created_at DESC,id);
CREATE FUNCTION uem_device_assignment_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'device assignment evidence cannot be deleted'; END IF;
 IF OLD.completed_at IS NOT NULL OR NEW.completed_at IS NULL OR
    (to_jsonb(NEW)-'completed_at') IS DISTINCT FROM (to_jsonb(OLD)-'completed_at') THEN
  RAISE EXCEPTION 'device assignment review cannot be replaced';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_device_assignment_immutable BEFORE UPDATE OR DELETE ON uem_device_assignment_reviews
 FOR EACH ROW EXECUTE FUNCTION uem_device_assignment_immutable();
