CREATE TABLE mdm_apple_push_reminders (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES mdm_apple_settings(tenant_id) ON DELETE CASCADE,
 fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
 expires_at TIMESTAMPTZ NOT NULL,
 stage INTEGER NOT NULL CHECK (stage IN (0,1,7,14,30)),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 resolved_at TIMESTAMPTZ,
 UNIQUE (tenant_id,fingerprint,stage)
);
CREATE TABLE mdm_apple_push_reminder_deliveries (
 id UUID PRIMARY KEY,
 reminder_id UUID NOT NULL REFERENCES mdm_apple_push_reminders(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','cancelled')),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
 next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 sent_at TIMESTAMPTZ,
 last_error TEXT NOT NULL DEFAULT '' CHECK (last_error IN ('','smtp_unavailable','smtp_failed','recipient_unavailable','superseded')),
 UNIQUE (reminder_id,user_id)
);
CREATE INDEX mdm_apple_push_reminder_due ON mdm_apple_push_reminder_deliveries(next_attempt_at,id) WHERE status='pending';
CREATE INDEX mdm_apple_push_reminder_history ON mdm_apple_push_reminders(tenant_id,created_at DESC);
