-- Pause affects future scheduling; it never claims to recall a sent mutation.
ALTER TABLE mdm_apple_mac_admin_accounts ADD COLUMN rotation_paused BOOLEAN NOT NULL DEFAULT false;
