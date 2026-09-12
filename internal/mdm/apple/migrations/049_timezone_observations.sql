CREATE TABLE mdm_apple_timezone_observations (
 device_id UUID PRIMARY KEY REFERENCES mdm_apple_devices(id) ON DELETE CASCADE,
 name TEXT NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 128),
 source TEXT NOT NULL CHECK(source='device_information'),
 recorded_at TIMESTAMPTZ NOT NULL
);
