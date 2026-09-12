ALTER TABLE mdm_apple_settings
 ADD COLUMN push_checked_at TIMESTAMPTZ,
 ADD COLUMN push_fingerprint TEXT NOT NULL DEFAULT '',
 ADD CONSTRAINT mdm_apple_settings_connection_check
 CHECK ((push_checked_at IS NULL AND push_fingerprint='')
     OR (push_checked_at IS NOT NULL AND push_fingerprint ~ '^[0-9a-f]{64}$'));
