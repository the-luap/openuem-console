-- Provider cleanup retries are explicit, permanent attempts. They reference
-- the original immutable key evidence and encrypted provider snapshot. No
-- foreign key may wait for the caller's outer request lock.
CREATE TABLE uem_netbird_cleanup_retries (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 request_id UUID NOT NULL,
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 revision TEXT NOT NULL CHECK(revision ~ '^[0-9a-f]{64}$'),
 key_id TEXT NOT NULL CHECK(key_id ~ '^[A-Za-z0-9_-]{1,128}$'),
 digest TEXT NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 sequence BIGINT NOT NULL CHECK(sequence>0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(request_id,sequence)
);
CREATE FUNCTION uem_netbird_cleanup_retry_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird cleanup attempts are permanent'; END $$;
CREATE TRIGGER uem_netbird_cleanup_retry_immutable BEFORE UPDATE OR DELETE ON uem_netbird_cleanup_retries FOR EACH ROW EXECUTE FUNCTION uem_netbird_cleanup_retry_immutable();

CREATE FUNCTION uem_netbird_cleanup_retry_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_registrations%ROWTYPE;
BEGIN
 SELECT * INTO r FROM uem_netbird_registrations WHERE id=NEW.request_id AND status='unconfirmed' AND released_at IS NULL;
 IF NOT FOUND
 OR NOT EXISTS(SELECT 1 FROM uem_netbird_registration_attempts WHERE request_id=r.id AND revision=r.revision AND stage='delete' AND digest=NEW.digest)
 OR NOT EXISTS(SELECT 1 FROM uem_netbird_registration_evidence WHERE request_id=r.id AND kind='key' AND data->>'ID'=NEW.key_id)
 OR EXISTS(SELECT 1 FROM uem_netbird_registration_evidence WHERE request_id=r.id AND kind='absent')
 THEN RAISE EXCEPTION 'Cleanup retry requires the exact unresolved key and original deletion attempt'; END IF;
 IF NEW.sequence<>(SELECT coalesce(max(sequence),0)+1 FROM uem_netbird_cleanup_retries WHERE request_id=r.id) THEN RAISE EXCEPTION 'Cleanup retry sequence is invalid'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_cleanup_retry_valid BEFORE INSERT ON uem_netbird_cleanup_retries FOR EACH ROW EXECUTE FUNCTION uem_netbird_cleanup_retry_valid();
