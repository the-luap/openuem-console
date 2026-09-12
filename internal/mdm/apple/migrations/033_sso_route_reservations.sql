-- Reservations retain the exact profile revisions that may still be installed.
-- Routing values and provider credentials remain in encrypted profile history.
ALTER TABLE mdm_apple_profile_revisions ADD CONSTRAINT mdm_apple_profile_revision_reference
 UNIQUE(tenant_id,profile_id,revision,id);
CREATE TABLE mdm_apple_sso_reservations (
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 user_channel_id UUID,
 profile_id UUID NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0),
 profile_revision_id UUID,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,device_id,user_channel_id) REFERENCES mdm_apple_users(tenant_id,device_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,profile_id,revision,profile_revision_id) REFERENCES mdm_apple_profile_revisions(tenant_id,profile_id,revision,id)
);
CREATE UNIQUE INDEX mdm_apple_sso_reservation_owner ON mdm_apple_sso_reservations
 (tenant_id,device_id,COALESCE(user_channel_id,'00000000-0000-0000-0000-000000000000'::uuid),profile_id,revision);
-- Missing historical snapshots cannot be reconstructed. A NULL reference keeps
-- that ambiguity visible until a fresh replacement or removal is verified.
INSERT INTO mdm_apple_sso_reservations(tenant_id,device_id,profile_id,revision,profile_revision_id,created_at)
 SELECT a.tenant_id,a.device_id,a.profile_id,a.revision,p.id,a.updated_at
 FROM mdm_apple_profile_assignments a LEFT JOIN mdm_apple_profile_revisions p
 ON p.tenant_id=a.tenant_id AND p.profile_id=a.profile_id AND p.revision=a.revision
 WHERE NOT(a.desired='removed' AND a.status='verified') AND (p.id IS NULL OR p.payload_types ? 'com.apple.extensiblesso');
INSERT INTO mdm_apple_sso_reservations(tenant_id,device_id,profile_id,revision,profile_revision_id,created_at)
 SELECT c.tenant_id,c.device_id,c.profile_id,c.profile_revision,p.id,c.created_at
 FROM mdm_apple_commands c JOIN mdm_apple_profile_assignments a
 ON a.tenant_id=c.tenant_id AND a.device_id=c.device_id AND a.profile_id=c.profile_id
 LEFT JOIN mdm_apple_profile_revisions p ON p.tenant_id=c.tenant_id AND p.profile_id=c.profile_id AND p.revision=c.profile_revision
 WHERE c.request_type='InstallProfile' AND c.attempts>0 AND a.status<>'verified'
 AND (p.id IS NULL OR p.payload_types ? 'com.apple.extensiblesso') ON CONFLICT DO NOTHING;
INSERT INTO mdm_apple_sso_reservations(tenant_id,device_id,user_channel_id,profile_id,revision,profile_revision_id,created_at)
 SELECT a.tenant_id,a.device_id,a.user_channel_id,a.profile_id,a.revision,p.id,a.updated_at
 FROM mdm_apple_user_assignments a LEFT JOIN mdm_apple_profile_revisions p
 ON p.tenant_id=a.tenant_id AND p.profile_id=a.profile_id AND p.revision=a.revision
 WHERE NOT(a.desired='removed' AND a.status='verified') AND (p.id IS NULL OR p.payload_types ? 'com.apple.extensiblesso');
INSERT INTO mdm_apple_sso_reservations(tenant_id,device_id,user_channel_id,profile_id,revision,profile_revision_id,created_at)
 SELECT c.tenant_id,c.device_id,c.user_channel_id,c.profile_id,c.profile_revision,p.id,c.created_at
 FROM mdm_apple_user_commands c JOIN mdm_apple_user_assignments a
 ON a.tenant_id=c.tenant_id AND a.user_channel_id=c.user_channel_id AND a.profile_id=c.profile_id
 LEFT JOIN mdm_apple_profile_revisions p ON p.tenant_id=c.tenant_id AND p.profile_id=c.profile_id AND p.revision=c.profile_revision
 WHERE c.request_type='InstallProfile' AND c.attempts>0 AND a.status<>'verified'
 AND (p.id IS NULL OR p.payload_types ? 'com.apple.extensiblesso') ON CONFLICT DO NOTHING;
