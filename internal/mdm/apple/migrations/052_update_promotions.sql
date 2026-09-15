CREATE TABLE mdm_apple_update_promotions (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES tenants(id),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 request_key UUID NOT NULL,
 pilot_plan_id UUID NOT NULL,
 pilot_assignment_id UUID NOT NULL,
 destination_plan_id UUID NOT NULL,
 assignment_id UUID NOT NULL UNIQUE,
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 actor_revision BIGINT NOT NULL CHECK(actor_revision>=0),
 created_at TIMESTAMPTZ NOT NULL,
 encrypted_intent BYTEA NOT NULL CHECK(octet_length(encrypted_intent) BETWEEN 29 AND 131100),
 UNIQUE(tenant_id,site_id,request_key),
 CHECK(assignment_id<>pilot_assignment_id),
 FOREIGN KEY(pilot_assignment_id,tenant_id,site_id,pilot_plan_id)
  REFERENCES mdm_apple_update_group_assignments(id,tenant_id,site_id,plan_id),
 FOREIGN KEY(assignment_id,tenant_id,site_id,destination_plan_id)
  REFERENCES mdm_apple_update_group_assignments(id,tenant_id,site_id,plan_id)
);
CREATE INDEX mdm_apple_update_promotion_history
 ON mdm_apple_update_promotions(tenant_id,site_id,pilot_plan_id,pilot_assignment_id,created_at DESC,id DESC);
CREATE FUNCTION mdm_apple_keep_update_promotion() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'Original Apple update promotions are immutable';
END;
$$;
CREATE TRIGGER mdm_apple_keep_update_promotion BEFORE UPDATE OR DELETE
 ON mdm_apple_update_promotions FOR EACH ROW EXECUTE FUNCTION mdm_apple_keep_update_promotion();
