-- The public invitation is claimed only by an explicit same-origin POST. The
-- individual profile is encrypted for bounded retries by that browser alone.
CREATE TABLE mdm_apple_enrollment_claims (
 device_id UUID PRIMARY KEY REFERENCES mdm_apple_devices(id) ON DELETE CASCADE,
 invite_hash TEXT NOT NULL UNIQUE,
 browser_hash TEXT NOT NULL,
 profile BYTEA,
 download_count INTEGER NOT NULL DEFAULT 0 CHECK (download_count BETWEEN 0 AND 3),
 download_expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '10 minutes',
 status_expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '1 hour'
);
CREATE INDEX mdm_apple_enrollment_claim_expiry ON mdm_apple_enrollment_claims(status_expires_at);
