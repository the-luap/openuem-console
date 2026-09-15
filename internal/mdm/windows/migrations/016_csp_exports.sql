ALTER TABLE mdm_windows_csp_audit DROP CONSTRAINT mdm_windows_csp_audit_action_check;
ALTER TABLE mdm_windows_csp_audit ADD CONSTRAINT mdm_windows_csp_audit_action_check
    CHECK (action IN ('command.queued','command.replayed','command.read','command.canceled','command.expired','command.blocked','command.sent','command.observed','command.acknowledged','command.failed','command.unknown','command.abandoned','command.authority_lost','command.exported','command.observation_exported'));
