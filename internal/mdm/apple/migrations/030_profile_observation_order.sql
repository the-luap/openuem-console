-- Retain the query time of an accepted inventory snapshot. Receipt time alone
-- cannot order reports from distinct queries that return after NotNow. Existing
-- inventory has no reliable query provenance; the next accepted query establishes
-- the watermark without inventing a historical observation time.
ALTER TABLE mdm_apple_devices ADD COLUMN profiles_query_at TIMESTAMPTZ;
ALTER TABLE mdm_apple_users ADD COLUMN profiles_query_at TIMESTAMPTZ;
