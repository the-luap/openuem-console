-- Scheduling metadata grants no authority to release certificate renewal. The
-- registry separately retains an authenticated admission and signed proof.
ALTER TABLE mdm_apple_filevault_rotations
 ADD COLUMN history_next_check_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 ADD COLUMN history_status TEXT NOT NULL DEFAULT 'waiting' CHECK(history_status IN ('waiting','checking','attention','complete'));
CREATE INDEX mdm_apple_filevault_history_check ON mdm_apple_filevault_rotations(history_next_check_at,id)
 WHERE status NOT IN ('queued','uncertain');
