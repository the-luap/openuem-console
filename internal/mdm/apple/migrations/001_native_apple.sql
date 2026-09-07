CREATE TABLE IF NOT EXISTS mdm_apple_settings (
 tenant_id BIGINT PRIMARY KEY CHECK (tenant_id > 0),
 public_url TEXT NOT NULL,
 organization TEXT NOT NULL,
 topic TEXT NOT NULL,
 push_expires_at TIMESTAMPTZ NOT NULL,
 push_certificate BYTEA NOT NULL,
 push_key BYTEA NOT NULL,
 ca_certificate BYTEA NOT NULL,
 ca_key BYTEA NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS mdm_apple_devices (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES mdm_apple_settings(tenant_id),
 site_id BIGINT NOT NULL CHECK (site_id > 0),
 udid TEXT,
 name TEXT NOT NULL DEFAULT '',
 serial_number TEXT NOT NULL DEFAULT '',
 model TEXT NOT NULL DEFAULT '',
 os_version TEXT NOT NULL DEFAULT '',
 build_version TEXT NOT NULL DEFAULT '',
 supervised BOOLEAN NOT NULL DEFAULT false,
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','authenticating','enrolled','unenrolled','revoked')),
 invite_hash TEXT UNIQUE,
 invite_expires_at TIMESTAMPTZ NOT NULL,
 certificate_fingerprint TEXT UNIQUE,
 certificate_expires_at TIMESTAMPTZ NOT NULL,
 push_token BYTEA,
 push_magic BYTEA,
 enrolled_at TIMESTAMPTZ,
 last_seen TIMESTAMPTZ,
 inventory_at TIMESTAMPTZ,
 apps_at TIMESTAMPTZ,
 profiles_at TIMESTAMPTZ,
 inventory JSONB NOT NULL DEFAULT '{}',
 apps JSONB NOT NULL DEFAULT '[]',
 installed_profiles JSONB NOT NULL DEFAULT '[]',
 ddm_status JSONB NOT NULL DEFAULT '{}',
 next_push_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 push_status TEXT NOT NULL DEFAULT 'pending',
 push_error TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE (tenant_id, udid),
 UNIQUE (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS mdm_apple_devices_scope ON mdm_apple_devices(tenant_id,site_id);
CREATE TABLE IF NOT EXISTS mdm_apple_profiles (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES mdm_apple_settings(tenant_id),
 name TEXT NOT NULL,
 identifier TEXT NOT NULL,
 payload_uuid TEXT NOT NULL,
 revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
 payload_types JSONB NOT NULL,
 payload BYTEA NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE (tenant_id, identifier),
 UNIQUE (tenant_id,id)
);
CREATE TABLE IF NOT EXISTS mdm_apple_commands (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 request_type TEXT NOT NULL,
 payload BYTEA NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','sent','acknowledged','failed','not_now','cancelled','expired')),
 attempts INTEGER NOT NULL DEFAULT 0,
 error TEXT NOT NULL DEFAULT '',
 profile_id UUID,
 profile_revision INTEGER,
 available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '7 days',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 completed_at TIMESTAMPTZ,
 FOREIGN KEY (tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id) ON DELETE CASCADE,
 FOREIGN KEY (tenant_id,profile_id) REFERENCES mdm_apple_profiles(tenant_id,id)
);
CREATE INDEX IF NOT EXISTS mdm_apple_commands_queue ON mdm_apple_commands(device_id,status,available_at,created_at);
CREATE TABLE IF NOT EXISTS mdm_apple_profile_assignments (
 tenant_id BIGINT NOT NULL,
 profile_id UUID NOT NULL,
 device_id UUID NOT NULL,
 revision INTEGER NOT NULL,
 desired TEXT NOT NULL CHECK (desired IN ('installed','removed')),
 status TEXT NOT NULL DEFAULT 'pending',
 error TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (profile_id,device_id),
 FOREIGN KEY (tenant_id,profile_id) REFERENCES mdm_apple_profiles(tenant_id,id),
 FOREIGN KEY (tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS mdm_apple_update_policies (
 tenant_id BIGINT NOT NULL,
 device_id UUID PRIMARY KEY,
 target_version TEXT NOT NULL,
 target_build TEXT NOT NULL DEFAULT '',
 deadline TEXT NOT NULL,
 details_url TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'pending',
 error TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 FOREIGN KEY (tenant_id,device_id) REFERENCES mdm_apple_devices(tenant_id,id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS mdm_apple_audit (
 id BIGSERIAL PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 actor TEXT NOT NULL,
 action TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 details JSONB NOT NULL DEFAULT '{}',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mdm_apple_audit_scope ON mdm_apple_audit(tenant_id,created_at DESC);
