ALTER TABLE mdm_apple_push_requests
 ADD COLUMN vendor_request BYTEA,
 ADD COLUMN vendor_fingerprint TEXT NOT NULL DEFAULT '',
 ADD COLUMN vendor_expires_at TIMESTAMPTZ,
 ADD CONSTRAINT mdm_apple_push_request_vendor_fields CHECK (
  (vendor_request IS NULL AND vendor_fingerprint='' AND vendor_expires_at IS NULL)
  OR (vendor_request IS NOT NULL AND vendor_fingerprint ~ '^[0-9a-f]{64}$' AND vendor_expires_at IS NOT NULL)
 );
