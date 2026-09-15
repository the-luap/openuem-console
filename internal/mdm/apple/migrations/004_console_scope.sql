-- The console creates the upstream schema before initializing native Apple
-- management. Restrict deletion so concurrent console actions cannot orphan an
-- identity after the application's user-friendly preflight check.
ALTER TABLE mdm_apple_settings ADD CONSTRAINT mdm_apple_settings_tenant_fk
 FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
ALTER TABLE mdm_apple_devices ADD CONSTRAINT mdm_apple_devices_site_fk
 FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE RESTRICT;
