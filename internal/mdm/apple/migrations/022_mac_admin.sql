ALTER TABLE mdm_apple_ade_profiles ADD COLUMN admin_options JSONB;
ALTER TABLE mdm_apple_ade_profiles ADD CONSTRAINT mdm_apple_ade_admin_options
 CHECK(admin_options IS NULL OR (jsonb_typeof(admin_options)='object' AND platform='macos' AND await_configuration));
CREATE FUNCTION mdm_apple_ade_admin_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.admin_options IS DISTINCT FROM OLD.admin_options THEN
  RAISE EXCEPTION 'ADE administrator policy versions are immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_ade_admin_immutable BEFORE UPDATE ON mdm_apple_ade_profiles
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_ade_admin_immutable();

-- Policies are inherited from the immutable admission. Secrets are per device.
CREATE TABLE mdm_apple_mac_admin_accounts (
 device_id UUID PRIMARY KEY REFERENCES mdm_apple_ade_admissions(device_id),
 tenant_id BIGINT NOT NULL,
 options JSONB NOT NULL CHECK(jsonb_typeof(options)='object'),
 creation_state TEXT NOT NULL DEFAULT 'planned' CHECK(creation_state IN ('planned','queued','sent','not_now','accepted','failed','uncertain','expired','cancelled')),
 guid UUID,
 inventory_state TEXT NOT NULL DEFAULT 'unknown' CHECK(inventory_state IN ('unknown','present','missing','conflict')),
 observed_at TIMESTAMPTZ,
 accepted_at TIMESTAMPTZ,
 current_key_id UUID,
 next_rotation_at TIMESTAMPTZ,
 next_check_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 error TEXT NOT NULL DEFAULT '',
 UNIQUE(tenant_id,device_id),
 FOREIGN KEY(tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id)
);
CREATE INDEX mdm_apple_mac_admin_due ON mdm_apple_mac_admin_accounts(next_check_at,device_id);
CREATE FUNCTION mdm_apple_mac_admin_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.device_id,NEW.tenant_id,NEW.options) IS DISTINCT FROM ROW(OLD.device_id,OLD.tenant_id,OLD.options)
    OR (OLD.guid IS NOT NULL AND NEW.guid IS DISTINCT FROM OLD.guid) THEN
  RAISE EXCEPTION 'Managed administrator policy and bound account identity are immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_mac_admin_immutable BEFORE UPDATE ON mdm_apple_mac_admin_accounts
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_mac_admin_immutable();

CREATE TABLE mdm_apple_mac_admin_keys (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 password BYTEA NOT NULL,
 operation TEXT NOT NULL CHECK(operation IN ('create','rotate')),
 status TEXT NOT NULL CHECK(status IN ('queued','sent','not_now','acknowledged','failed','uncertain','expired','cancelled')),
 command_id UUID NOT NULL UNIQUE REFERENCES mdm_apple_commands(id),
 dispatched_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 completed_at TIMESTAMPTZ,
 UNIQUE(device_id,id),
 FOREIGN KEY(tenant_id,device_id) REFERENCES mdm_apple_mac_admin_accounts(tenant_id,device_id)
);
CREATE UNIQUE INDEX mdm_apple_mac_admin_one_active ON mdm_apple_mac_admin_keys(device_id)
 WHERE status IN ('queued','sent','not_now','uncertain');
ALTER TABLE mdm_apple_mac_admin_accounts ADD CONSTRAINT mdm_apple_mac_admin_current_key
 FOREIGN KEY(device_id,current_key_id) REFERENCES mdm_apple_mac_admin_keys(device_id,id);
ALTER TABLE mdm_apple_commands ADD COLUMN mac_admin BOOLEAN NOT NULL DEFAULT false;
