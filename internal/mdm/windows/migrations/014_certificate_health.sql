ALTER TABLE mdm_windows_console_audit DROP CONSTRAINT mdm_windows_console_audit_action_check;
ALTER TABLE mdm_windows_console_audit ADD CONSTRAINT mdm_windows_console_audit_action_check
    CHECK (action IN ('invitations.list','devices.list','device.read','device.revoked','authority.status','certificate_health.read'));
