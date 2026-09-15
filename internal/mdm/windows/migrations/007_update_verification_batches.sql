-- Preserve existing immutable runs and ciphertext. Version 1 retains steps 0..2;
-- version 2 reserves preflight, one Atomic configuration and up to five read batches.
ALTER TABLE mdm_windows_csp_commands DROP CONSTRAINT mdm_windows_csp_update_identity;
ALTER TABLE mdm_windows_csp_commands ADD CONSTRAINT mdm_windows_csp_update_identity
    CHECK ((update_run_id IS NULL AND update_step IS NULL) OR (update_run_id IS NOT NULL AND update_step IS NOT NULL AND update_step BETWEEN 0 AND 6 AND NOT user_target));
