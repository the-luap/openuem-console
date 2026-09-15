ALTER TABLE mdm_apple_update_group_assignments
 ADD CONSTRAINT mdm_apple_update_group_original_scope UNIQUE(id,tenant_id,site_id,plan_id);

CREATE TABLE mdm_apple_update_group_removals (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES tenants(id),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 request_key UUID NOT NULL,
 plan_id UUID NOT NULL,
 assignment_id UUID NOT NULL,
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 actor_revision BIGINT NOT NULL CHECK(actor_revision>=0),
 created_at TIMESTAMPTZ NOT NULL,
 encrypted_intent BYTEA NOT NULL CHECK(octet_length(encrypted_intent) BETWEEN 29 AND 32796),
 UNIQUE(tenant_id,site_id,request_key),
 FOREIGN KEY(assignment_id,tenant_id,site_id,plan_id)
  REFERENCES mdm_apple_update_group_assignments(id,tenant_id,site_id,plan_id)
);
CREATE INDEX mdm_apple_update_group_removal_history ON mdm_apple_update_group_removals
 (tenant_id,site_id,plan_id,assignment_id,created_at DESC,id DESC);
CREATE FUNCTION mdm_apple_keep_update_group_removal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'Original Apple update group removals are immutable';
END;
$$;
CREATE TRIGGER mdm_apple_keep_update_group_removal BEFORE UPDATE OR DELETE
 ON mdm_apple_update_group_removals FOR EACH ROW EXECUTE FUNCTION mdm_apple_keep_update_group_removal();
