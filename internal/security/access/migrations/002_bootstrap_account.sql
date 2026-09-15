-- Retain the first-account binding independently of account deletion and audit
-- retention. A restart must never recreate an account or restore its old grants.
CREATE TABLE IF NOT EXISTS uem_access_bootstrap_account (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    user_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
