-- Inactive history must not occupy the bounded maintenance batch.
CREATE INDEX mdm_apple_mac_admin_creation_due ON mdm_apple_mac_admin_accounts(next_check_at,device_id)
 WHERE creation_state='planned';
CREATE INDEX mdm_apple_mac_admin_rotation_due ON mdm_apple_mac_admin_accounts(next_rotation_at,device_id)
 WHERE NOT rotation_paused AND next_rotation_at IS NOT NULL;
