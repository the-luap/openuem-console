ALTER TABLE mdm_apple_devices ADD COLUMN update_exception_scope_revision BIGINT NOT NULL DEFAULT 0 CHECK(update_exception_scope_revision>=0);
CREATE FUNCTION mdm_apple_update_exception_scope_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 NEW.update_exception_scope_revision := OLD.update_exception_scope_revision;
 IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.site_id IS DISTINCT FROM OLD.site_id THEN
  NEW.update_exception_scope_revision := OLD.update_exception_scope_revision+1;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_update_exception_scope_change BEFORE UPDATE OF tenant_id,site_id,update_exception_scope_revision
 ON mdm_apple_devices FOR EACH ROW EXECUTE FUNCTION mdm_apple_update_exception_scope_change();

CREATE TABLE mdm_apple_update_exceptions (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES tenants(id),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 device_id UUID NOT NULL,
 scope_revision BIGINT NOT NULL CHECK(scope_revision>=0),
 revision INTEGER NOT NULL CHECK(revision>0),
 previous_id UUID,
 request_key UUID NOT NULL,
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 actor_revision BIGINT NOT NULL CHECK(actor_revision>=0),
 kind TEXT NOT NULL CHECK(kind IN ('pause','resume')),
 created_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ,
 encrypted_intent BYTEA NOT NULL CHECK(octet_length(encrypted_intent) BETWEEN 29 AND 32796),
 UNIQUE(tenant_id,site_id,device_id,revision),
 UNIQUE(tenant_id,site_id,request_key),
 UNIQUE(id,tenant_id,site_id,device_id),
 FOREIGN KEY(previous_id,tenant_id,site_id,device_id)
  REFERENCES mdm_apple_update_exceptions(id,tenant_id,site_id,device_id),
 CHECK((revision=1 AND previous_id IS NULL) OR (revision>1 AND previous_id IS NOT NULL)),
 CHECK((kind='pause' AND expires_at IS NOT NULL AND expires_at>created_at AND expires_at<=created_at+interval '30 days') OR (kind='resume' AND expires_at IS NULL))
);
CREATE INDEX mdm_apple_update_exception_history ON mdm_apple_update_exceptions
 (tenant_id,site_id,device_id,revision DESC);
CREATE FUNCTION mdm_apple_keep_update_exception() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'Original Apple update exception events are immutable';
END;
$$;
CREATE TRIGGER mdm_apple_keep_update_exception BEFORE UPDATE OR DELETE
 ON mdm_apple_update_exceptions FOR EACH ROW EXECUTE FUNCTION mdm_apple_keep_update_exception();
