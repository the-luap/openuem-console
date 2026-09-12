-- Reviewed Apple update plans are separate from live per-device policy state.
CREATE TABLE mdm_apple_update_plans (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES tenants(id),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 revision INTEGER NOT NULL CHECK(revision>0),
 UNIQUE(id,tenant_id,site_id)
);
CREATE TABLE mdm_apple_update_plan_revisions (
 plan_id UUID NOT NULL,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 created_at TIMESTAMPTZ NOT NULL,
 encrypted_definition BYTEA NOT NULL CHECK(octet_length(encrypted_definition) BETWEEN 29 AND 8220),
 PRIMARY KEY(plan_id,revision),
 FOREIGN KEY(plan_id,tenant_id,site_id) REFERENCES mdm_apple_update_plans(id,tenant_id,site_id)
);
ALTER TABLE mdm_apple_update_plans ADD CONSTRAINT mdm_apple_update_plan_current_revision
 FOREIGN KEY(id,revision) REFERENCES mdm_apple_update_plan_revisions(plan_id,revision)
 DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX mdm_apple_update_plan_scope ON mdm_apple_update_plans(tenant_id,site_id,id);
CREATE FUNCTION mdm_apple_keep_update_plan_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'Apple update plan revisions are immutable';
END;
$$;
CREATE TRIGGER mdm_apple_keep_update_plan_revision BEFORE UPDATE OR DELETE
 ON mdm_apple_update_plan_revisions FOR EACH ROW EXECUTE FUNCTION mdm_apple_keep_update_plan_revision();
CREATE FUNCTION mdm_apple_keep_update_plan_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Apple update plans must be archived'; END IF;
 IF NEW.id<>OLD.id OR NEW.tenant_id<>OLD.tenant_id OR NEW.site_id<>OLD.site_id OR NEW.revision<>OLD.revision+1 THEN
  RAISE EXCEPTION 'Apple update plans retain scope and advance one revision';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_keep_update_plan_identity BEFORE UPDATE OR DELETE
 ON mdm_apple_update_plans FOR EACH ROW EXECUTE FUNCTION mdm_apple_keep_update_plan_identity();
