-- Existing attempts retain their original evidence; never invent a wire digest
-- for a message that was not captured by the versioned command integration.
ALTER TABLE uem_netbird_operation_attempts
 ADD COLUMN command_hash TEXT CHECK(command_hash IS NULL OR command_hash ~ '^[0-9a-f]{64}$'),
 ADD COLUMN command_expires_at TIMESTAMPTZ,
 ADD CONSTRAINT uem_netbird_attempt_wire_pair CHECK((command_hash IS NULL)=(command_expires_at IS NULL));

DO $$
DECLARE guard RECORD; found INTEGER:=0;
BEGIN
 FOR guard IN SELECT conname FROM pg_catalog.pg_constraint
  WHERE conrelid='uem_netbird_operations'::regclass AND contype='c'
   AND pg_catalog.pg_get_constraintdef(oid) LIKE '%jsonb_build_object%' LOOP
  found:=found+1;
  EXECUTE format('ALTER TABLE uem_netbird_operations DROP CONSTRAINT %I',guard.conname);
 END LOOP;
 IF found<>1 THEN RAISE EXCEPTION 'NetBird result validation is incomplete'; END IF;
END $$;

ALTER TABLE uem_netbird_operations ADD CONSTRAINT uem_netbird_result_shape CHECK(
 result IS NULL OR (
  result-'command_hash'=jsonb_build_object('request_id',id::text,'device_id',device_id,'revision',revision,'operation',operation,'success',true)
  AND (NOT result ? 'command_hash' OR (jsonb_typeof(result->'command_hash')='string' AND result->>'command_hash' ~ '^[0-9a-f]{64}$'))
 ));

-- New completion requires the actual prepared message digest. Historical
-- completed rows remain readable and immutable without manufacturing evidence.
CREATE FUNCTION uem_netbird_wire_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status='completed' AND (TG_OP='INSERT' OR OLD.status='queued') THEN
  IF NOT EXISTS(SELECT 1 FROM uem_netbird_operation_attempts a
   WHERE a.request_id=NEW.id AND a.command_hash=NEW.result->>'command_hash'
    AND a.command_expires_at>NEW.requested_at AND a.command_expires_at<=NEW.expires_at) THEN
   RAISE EXCEPTION 'NetBird result does not match its prepared command';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_wire_receipt BEFORE INSERT OR UPDATE ON uem_netbird_operations FOR EACH ROW EXECUTE FUNCTION uem_netbird_wire_receipt();
