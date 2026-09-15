-- Bound each assignment's history page without scanning unrelated attempts.
CREATE INDEX mdm_apple_app_attempt_history ON mdm_apple_app_attempts(assignment_id,created_at DESC,id DESC);
