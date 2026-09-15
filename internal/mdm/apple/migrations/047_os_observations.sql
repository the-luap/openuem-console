-- Current protocol observations for cohort reporting. Legacy merged inventory
-- is deliberately not backfilled as a newly verified version/build observation.
CREATE TABLE mdm_apple_os_observations (
 device_id UUID PRIMARY KEY REFERENCES mdm_apple_devices(id) ON DELETE CASCADE,
 version TEXT NOT NULL CHECK(octet_length(version) BETWEEN 1 AND 32),
 build TEXT NOT NULL CHECK(octet_length(build)<=32),
 source TEXT NOT NULL CHECK(source IN ('device_information','declarative_status')),
 recorded_at TIMESTAMPTZ NOT NULL
);
