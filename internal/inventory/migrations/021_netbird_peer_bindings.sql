-- Positive provider registration evidence is retained independently of mutable
-- inventory reports. No device deletion cascades into this history.
CREATE TABLE uem_netbird_peer_bindings (
 request_id UUID PRIMARY KEY,
 id UUID NOT NULL UNIQUE CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 revision TEXT NOT NULL CHECK(revision ~ '^[0-9a-f]{64}$'),
 provider_url TEXT NOT NULL CHECK(length(provider_url) BETWEEN 1 AND 2048 AND provider_url LIKE 'https://%'),
 event JSONB NOT NULL CHECK(jsonb_typeof(event)='object' AND octet_length(event::text)<=2048),
 peer JSONB NOT NULL CHECK(jsonb_typeof(peer)='object' AND octet_length(peer::text)<=8192),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION uem_netbird_peer_binding_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird provider peer associations are permanent'; END $$;
CREATE TRIGGER uem_netbird_peer_binding_immutable BEFORE UPDATE OR DELETE ON uem_netbird_peer_bindings FOR EACH ROW EXECUTE FUNCTION uem_netbird_peer_binding_immutable();

CREATE FUNCTION uem_netbird_peer_binding_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_registrations%ROWTYPE; k JSONB; e JSONB; p JSONB; event_at TIMESTAMPTZ; peer_at TIMESTAMPTZ;
BEGIN
 SELECT * INTO r FROM uem_netbird_registrations WHERE id=NEW.request_id AND status IN ('completed','unconfirmed');
 IF NOT FOUND
 OR NOT EXISTS(SELECT 1 FROM uem_netbird_registration_attempts WHERE request_id=r.id AND revision=r.revision AND stage='deliver')
 OR NOT EXISTS(SELECT 1 FROM uem_netbird_registration_evidence WHERE request_id=r.id AND kind='absent')
 THEN RAISE EXCEPTION 'Peer association requires retained delivery admission and key absence'; END IF;
 SELECT data INTO k FROM uem_netbird_registration_evidence WHERE request_id=r.id AND kind='key';
 IF NOT FOUND THEN RAISE EXCEPTION 'Peer association requires the original key'; END IF;
 e:=NEW.event; p:=NEW.peer;
 IF e IS DISTINCT FROM jsonb_build_object('ID',e->'ID','KeyID',k->'ID','PeerID',e->'PeerID','Timestamp',e->'Timestamp')
 OR NOT coalesce(e->>'ID' ~ '^[A-Za-z0-9_-]{1,128}$',false) OR e->>'ID'='0'
 OR jsonb_typeof(e->'ID') IS DISTINCT FROM 'string'
 OR NOT coalesce(e->>'PeerID' ~ '^[A-Za-z0-9_-]{1,128}$',false)
 OR jsonb_typeof(e->'PeerID') IS DISTINCT FROM 'string'
 OR jsonb_typeof(e->'Timestamp') IS DISTINCT FROM 'string'
 OR p IS DISTINCT FROM jsonb_build_object('ID',e->'PeerID','Name',p->'Name','UserID','','CreatedAt',p->'CreatedAt','Ephemeral',false)
 OR jsonb_typeof(p->'Name') IS DISTINCT FROM 'string' OR octet_length(p->>'Name')>1024 OR p->>'Name' ~ '[[:cntrl:]]'
 OR jsonb_typeof(p->'CreatedAt') IS DISTINCT FROM 'string'
 THEN RAISE EXCEPTION 'Peer association evidence is invalid'; END IF;
 event_at:=(e->>'Timestamp')::timestamptz; peer_at:=(p->>'CreatedAt')::timestamptz;
 IF NOT (peer_at>=r.requested_at-interval '5 minutes' AND peer_at<=event_at
 AND peer_at<=(k->>'ExpiresAt')::timestamptz
 AND event_at<=least((k->>'ExpiresAt')::timestamptz+interval '5 minutes',clock_timestamp()+interval '5 minutes'))
 THEN RAISE EXCEPTION 'Peer association timestamps do not match registration'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_peer_binding_valid BEFORE INSERT ON uem_netbird_peer_bindings FOR EACH ROW EXECUTE FUNCTION uem_netbird_peer_binding_valid();
