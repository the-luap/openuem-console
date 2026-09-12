CREATE TABLE uem_desktop_releases (
    digest TEXT PRIMARY KEY CHECK (digest ~ '^[0-9a-f]{64}$'),
    sequence BIGINT NOT NULL UNIQUE CHECK (sequence > 0),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
    published_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    signing_key_id TEXT NOT NULL CHECK (signing_key_id ~ '^[0-9a-f]{64}$'),
    envelope BYTEA NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 32768),
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    accepted_by TEXT NOT NULL CHECK (length(accepted_by) BETWEEN 1 AND 255),
    withdrawn_at TIMESTAMPTZ
);

CREATE TABLE uem_desktop_release_checkpoint (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    digest TEXT REFERENCES uem_desktop_releases(digest),
    CHECK ((sequence = 0 AND digest IS NULL) OR (sequence > 0 AND digest IS NOT NULL))
);
INSERT INTO uem_desktop_release_checkpoint(id,sequence) VALUES(1,0);

CREATE TABLE uem_desktop_release_audit (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 255),
    action TEXT NOT NULL CHECK (action IN ('release.accept','release.withdraw')),
    digest TEXT NOT NULL REFERENCES uem_desktop_releases(digest),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX uem_desktop_release_audit_created ON uem_desktop_release_audit(created_at DESC,id DESC);
