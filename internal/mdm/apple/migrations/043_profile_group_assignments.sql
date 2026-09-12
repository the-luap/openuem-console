-- Original reviewed group intent outlives the mutable profile catalog and group.
CREATE TABLE mdm_apple_profile_group_assignments (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES tenants(id),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 request_key UUID NOT NULL,
 profile_id UUID NOT NULL,
 profile_revision INTEGER NOT NULL CHECK(profile_revision>0),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 actor_revision BIGINT NOT NULL CHECK(actor_revision>=0),
 desired TEXT NOT NULL CHECK(desired IN ('installed','removed')),
 created_at TIMESTAMPTZ NOT NULL,
 encrypted_intent BYTEA NOT NULL CHECK(octet_length(encrypted_intent) BETWEEN 29 AND 16412),
 UNIQUE(tenant_id,site_id,request_key),
 FOREIGN KEY(tenant_id,profile_id,profile_revision)
   REFERENCES mdm_apple_profile_revisions(tenant_id,profile_id,revision)
);
CREATE INDEX mdm_apple_profile_group_history ON mdm_apple_profile_group_assignments
 (tenant_id,site_id,profile_id,created_at DESC,id DESC);
CREATE FUNCTION mdm_apple_keep_profile_group_assignment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'Original profile group assignments are immutable';
END;
$$;
CREATE TRIGGER mdm_apple_keep_profile_group_assignment BEFORE UPDATE OR DELETE
 ON mdm_apple_profile_group_assignments FOR EACH ROW
 EXECUTE FUNCTION mdm_apple_keep_profile_group_assignment();
