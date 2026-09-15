-- A global scope must resolve to one stable row, including during concurrent writes.
CREATE UNIQUE INDEX uem_settings_single_global ON settings ((true)) WHERE tenant_settings IS NULL;
ALTER TABLE settings ADD COLUMN uem_smtp_revision UUID NOT NULL DEFAULT gen_random_uuid();
CREATE FUNCTION uem_smtp_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.smtp_server,NEW.smtp_port,NEW.smtp_user,NEW.smtp_password,NEW.smtp_auth,NEW.message_from,NEW.smtp_encryption_type,NEW.tenant_settings)
 IS DISTINCT FROM ROW(OLD.smtp_server,OLD.smtp_port,OLD.smtp_user,OLD.smtp_password,OLD.smtp_auth,OLD.message_from,OLD.smtp_encryption_type,OLD.tenant_settings) THEN
  NEW.uem_smtp_revision := gen_random_uuid();
 ELSE
  NEW.uem_smtp_revision := OLD.uem_smtp_revision;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_smtp_revision BEFORE UPDATE ON settings FOR EACH ROW EXECUTE FUNCTION uem_smtp_revision();

-- Independent committed attempt evidence survives terminal transaction rollback.
-- No foreign keys: settings/account deletion must not allow a replay to resend.
CREATE TABLE uem_smtp_test_attempts (
 id UUID PRIMARY KEY,
 settings_id BIGINT NOT NULL CHECK (settings_id>0),
 tenant_id BIGINT NOT NULL CHECK (tenant_id>=0),
 revision UUID NOT NULL,
 actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 255),
 status TEXT NOT NULL DEFAULT 'attempted' CHECK (status IN ('attempted','sent','unconfirmed')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 finished_at TIMESTAMPTZ,
 CHECK ((status='attempted')=(finished_at IS NULL))
);
CREATE INDEX uem_smtp_test_settings_time ON uem_smtp_test_attempts(settings_id,created_at DESC);
