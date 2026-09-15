CREATE TABLE IF NOT EXISTS mdm_apple_software_catalog (
 singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
 document JSONB NOT NULL DEFAULT '{}',
 fetched_at TIMESTAMPTZ,
 attempted_at TIMESTAMPTZ,
 last_error TEXT NOT NULL DEFAULT ''
);
INSERT INTO mdm_apple_software_catalog(singleton) VALUES(true) ON CONFLICT DO NOTHING;
