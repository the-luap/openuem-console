ALTER TABLE uem_settings_audit DROP CONSTRAINT uem_settings_audit_action_check;
ALTER TABLE uem_settings_audit ADD CONSTRAINT uem_settings_audit_action_check CHECK (action IN (
 'settings.smtp.read','settings.smtp.update','settings.smtp.test_attempt','settings.smtp.test_sent','settings.smtp.test_unconfirmed','settings.smtp.secrets_migrate',
 'settings.netbird.read','settings.netbird.update','settings.netbird.secrets_migrate',
 'settings.netbird.packages.list','settings.netbird.packages.read','settings.netbird.packages.approve','settings.netbird.packages.revoke'
));
