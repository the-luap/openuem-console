-- Confirmation permits one exact-peer DELETE. Attempts commit independently;
-- only a separate positive read establishes absence. No inventory cascade.
CREATE TABLE uem_netbird_peer_removals (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 request_id UUID NOT NULL,
 binding_id UUID NOT NULL,
 binding_revision TEXT NOT NULL CHECK(binding_revision ~ '^[0-9a-f]{64}$'),
 peer_id TEXT NOT NULL CHECK(peer_id ~ '^[A-Za-z0-9_-]{1,128}$'),
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 revision TEXT NOT NULL CHECK(revision ~ '^[0-9a-f]{64}$'),
 sequence BIGINT NOT NULL CHECK(sequence>0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(request_id,sequence)
);
CREATE TABLE uem_netbird_peer_absence (
 request_id UUID PRIMARY KEY,
 binding_id UUID NOT NULL,
 peer_id TEXT NOT NULL CHECK(peer_id ~ '^[A-Za-z0-9_-]{1,128}$'),
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION uem_netbird_peer_removal_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird peer removal evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_peer_removal_immutable BEFORE UPDATE OR DELETE ON uem_netbird_peer_removals FOR EACH ROW EXECUTE FUNCTION uem_netbird_peer_removal_immutable();
CREATE FUNCTION uem_netbird_peer_absence_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird peer absence evidence is permanent'; END $$;
CREATE TRIGGER uem_netbird_peer_absence_immutable BEFORE UPDATE OR DELETE ON uem_netbird_peer_absence FOR EACH ROW EXECUTE FUNCTION uem_netbird_peer_absence_immutable();

CREATE FUNCTION uem_netbird_peer_removal_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE b uem_netbird_peer_bindings%ROWTYPE;
BEGIN
 SELECT * INTO b FROM uem_netbird_peer_bindings WHERE request_id=NEW.request_id AND id=NEW.binding_id AND peer->>'ID'=NEW.peer_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'Peer removal requires the exact retained association'; END IF;
 IF NEW.binding_revision<>b.revision
  OR EXISTS(SELECT 1 FROM uem_netbird_peer_absence WHERE request_id=NEW.request_id)
  OR NEW.sequence<>(SELECT coalesce(max(sequence),0)+1 FROM uem_netbird_peer_removals WHERE request_id=NEW.request_id)
 THEN RAISE EXCEPTION 'Peer removal attempt is invalid'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_peer_removal_valid BEFORE INSERT ON uem_netbird_peer_removals FOR EACH ROW EXECUTE FUNCTION uem_netbird_peer_removal_valid();
CREATE FUNCTION uem_netbird_peer_absence_valid() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM uem_netbird_peer_bindings WHERE request_id=NEW.request_id AND id=NEW.binding_id AND peer->>'ID'=NEW.peer_id)
 THEN RAISE EXCEPTION 'Peer absence requires the exact retained association'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_peer_absence_valid BEFORE INSERT ON uem_netbird_peer_absence FOR EACH ROW EXECUTE FUNCTION uem_netbird_peer_absence_valid();
