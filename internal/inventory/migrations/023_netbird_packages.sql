-- Exact package approvals and revocations survive device and organization
-- deletion. Source coordinates are encrypted; existing approvals never change.
CREATE TABLE uem_netbird_packages (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 tenant_id BIGINT NOT NULL CHECK(tenant_id>0),
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 platform TEXT NOT NULL CHECK(platform IN ('linux','macos')),
 architecture TEXT NOT NULL CHECK(architecture IN ('amd64','arm64','386')),
 format TEXT NOT NULL CHECK(format IN ('deb','rpm','pkg')),
 package_id TEXT NOT NULL,
 version TEXT NOT NULL CHECK(version ~ '^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}$'),
 size BIGINT NOT NULL CHECK(size BETWEEN 1 AND 536870912),
 sha256 TEXT NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 digest TEXT NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 verification TEXT NOT NULL CHECK(octet_length(verification) BETWEEN 1 AND 512),
 encrypted_descriptor BYTEA NOT NULL CHECK(octet_length(encrypted_descriptor) BETWEEN 29 AND 8220),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK((platform='linux' AND format IN ('deb','rpm') AND package_id='netbird')
  OR (platform='macos' AND format='pkg' AND package_id='io.netbird.client' AND architecture<>'386'))
);
CREATE INDEX uem_netbird_packages_organization ON uem_netbird_packages(tenant_id,created_at DESC,id DESC);
CREATE TABLE uem_netbird_package_revocations (
 approval_id UUID PRIMARY KEY REFERENCES uem_netbird_packages(id),
 id UUID NOT NULL UNIQUE CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 digest TEXT NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION uem_netbird_package_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird package approvals are permanent'; END $$;
CREATE TRIGGER uem_netbird_package_immutable BEFORE UPDATE OR DELETE ON uem_netbird_packages
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_package_immutable();
CREATE FUNCTION uem_netbird_package_revocation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird package revocations are permanent'; END $$;
CREATE TRIGGER uem_netbird_package_revocation_immutable BEFORE UPDATE OR DELETE ON uem_netbird_package_revocations
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_package_revocation_immutable();
CREATE FUNCTION uem_netbird_package_revocation_valid() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM uem_netbird_packages WHERE id=NEW.approval_id AND digest=NEW.digest)
 THEN RAISE EXCEPTION 'NetBird package revocation does not match the approval'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_package_revocation_valid BEFORE INSERT ON uem_netbird_package_revocations
 FOR EACH ROW EXECUTE FUNCTION uem_netbird_package_revocation_valid();
