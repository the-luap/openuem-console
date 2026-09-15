CREATE TABLE mdm_apple_update_group_assignments (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES tenants(id),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 request_key UUID NOT NULL,
 plan_id UUID NOT NULL,
 plan_revision INTEGER NOT NULL CHECK(plan_revision>0),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 actor_revision BIGINT NOT NULL CHECK(actor_revision>=0),
 created_at TIMESTAMPTZ NOT NULL,
 encrypted_intent BYTEA NOT NULL CHECK(octet_length(encrypted_intent) BETWEEN 29 AND 32796),
 UNIQUE(tenant_id,site_id,request_key),
 FOREIGN KEY(plan_id,tenant_id,site_id) REFERENCES mdm_apple_update_plans(id,tenant_id,site_id),
 FOREIGN KEY(plan_id,plan_revision) REFERENCES mdm_apple_update_plan_revisions(plan_id,revision)
);
CREATE INDEX mdm_apple_update_group_history ON mdm_apple_update_group_assignments
 (tenant_id,site_id,plan_id,created_at DESC,id DESC);
CREATE FUNCTION mdm_apple_keep_update_group_assignment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'Original Apple update group assignments are immutable';
END;
$$;
CREATE TRIGGER mdm_apple_keep_update_group_assignment BEFORE UPDATE OR DELETE
 ON mdm_apple_update_group_assignments FOR EACH ROW EXECUTE FUNCTION mdm_apple_keep_update_group_assignment();
