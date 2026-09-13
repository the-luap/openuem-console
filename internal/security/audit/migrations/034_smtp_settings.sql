CREATE TABLE uem_settings_audit (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id BIGINT NOT NULL CHECK (tenant_id>=0),
 site_id BIGINT NOT NULL DEFAULT 0 CHECK (site_id=0),
 actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 255),
 action TEXT NOT NULL CHECK (action IN ('settings.smtp.read','settings.smtp.update','settings.smtp.test_attempt','settings.smtp.test_sent','settings.smtp.test_unconfirmed','settings.smtp.secrets_migrate')),
 resource_id TEXT NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 512),
 result TEXT NOT NULL CHECK (result IN ('recorded','success','failure')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX uem_settings_audit_tenant ON uem_settings_audit(tenant_id,created_at DESC,id DESC);
