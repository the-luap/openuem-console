ALTER TABLE netbird_settings ADD COLUMN uem_netbird_revision UUID NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE tenants ADD COLUMN uem_netbird_revision UUID NOT NULL DEFAULT gen_random_uuid();
CREATE FUNCTION uem_netbird_settings_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.management_url,NEW.access_token) IS DISTINCT FROM ROW(OLD.management_url,OLD.access_token) THEN NEW.uem_netbird_revision:=gen_random_uuid();
 ELSE NEW.uem_netbird_revision:=OLD.uem_netbird_revision; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_settings_revision BEFORE UPDATE ON netbird_settings FOR EACH ROW EXECUTE FUNCTION uem_netbird_settings_revision();
CREATE FUNCTION uem_netbird_tenant_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.tenant_netbird IS DISTINCT FROM OLD.tenant_netbird THEN NEW.uem_netbird_revision:=gen_random_uuid();
 ELSE NEW.uem_netbird_revision:=OLD.uem_netbird_revision; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_tenant_revision BEFORE UPDATE ON tenants FOR EACH ROW EXECUTE FUNCTION uem_netbird_tenant_revision();
