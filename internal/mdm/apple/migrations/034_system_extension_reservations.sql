-- Potentially installed extension policies keep their retained revision identity
-- until replacement/removal is confirmed by fresh native profile inventory.
CREATE TABLE mdm_apple_system_extension_reservations (
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 profile_id UUID NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0),
 profile_revision_id UUID,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,device_id,profile_id,revision),
 FOREIGN KEY(tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,profile_id,revision,profile_revision_id) REFERENCES mdm_apple_profile_revisions(tenant_id,profile_id,revision,id)
);
INSERT INTO mdm_apple_system_extension_reservations(tenant_id,device_id,profile_id,revision,profile_revision_id,created_at)
 SELECT a.tenant_id,a.device_id,a.profile_id,a.revision,p.id,a.updated_at
 FROM mdm_apple_profile_assignments a LEFT JOIN mdm_apple_profile_revisions p
 ON p.tenant_id=a.tenant_id AND p.profile_id=a.profile_id AND p.revision=a.revision
 WHERE NOT(a.desired='removed' AND a.status='verified') AND (p.id IS NULL OR p.payload_types ? 'com.apple.system-extension-policy');
INSERT INTO mdm_apple_system_extension_reservations(tenant_id,device_id,profile_id,revision,profile_revision_id,created_at)
 SELECT c.tenant_id,c.device_id,c.profile_id,c.profile_revision,p.id,c.created_at
 FROM mdm_apple_commands c JOIN mdm_apple_profile_assignments a
 ON a.tenant_id=c.tenant_id AND a.device_id=c.device_id AND a.profile_id=c.profile_id
 LEFT JOIN mdm_apple_profile_revisions p ON p.tenant_id=c.tenant_id AND p.profile_id=c.profile_id AND p.revision=c.profile_revision
 WHERE c.request_type='InstallProfile' AND c.attempts>0 AND a.status<>'verified'
 AND (p.id IS NULL OR p.payload_types ? 'com.apple.system-extension-policy') ON CONFLICT DO NOTHING;
