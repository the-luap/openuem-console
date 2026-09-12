-- Device and user requests share the enrollment certificate, but never their
-- push credentials, command queues, profile inventory or assignment state.
ALTER TABLE mdm_apple_devices ADD COLUMN per_user_connections BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE mdm_apple_enrollment_layouts ADD COLUMN per_user_connections BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE mdm_apple_profiles ADD COLUMN payload_scope TEXT NOT NULL DEFAULT 'System' CHECK(payload_scope IN ('System','User'));
ALTER TABLE mdm_apple_profiles ADD CONSTRAINT mdm_apple_profile_scope UNIQUE(tenant_id,id);

CREATE TABLE mdm_apple_users (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 user_id UUID NOT NULL CHECK(user_id <> '00000000-0000-0000-0000-000000000000' AND user_id <> 'ffffffff-ffff-ffff-ffff-ffffffffffff'),
 short_name TEXT NOT NULL DEFAULT '',
 long_name TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','enrolled','blocked','not_managed')),
 not_on_console BOOLEAN NOT NULL DEFAULT false,
 push_token BYTEA,
 push_magic BYTEA,
 push_status TEXT NOT NULL DEFAULT 'pending',
 push_error TEXT NOT NULL DEFAULT '',
 next_push_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 first_seen TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 last_seen TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 profiles_at TIMESTAMPTZ,
 next_inventory_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 installed_profiles JSONB NOT NULL DEFAULT '[]',
 UNIQUE(device_id,user_id),
 UNIQUE(tenant_id,device_id,id),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES mdm_apple_devices(tenant_id,site_id,id) ON DELETE CASCADE,
 CHECK((push_token IS NULL)=(push_magic IS NULL))
);
CREATE INDEX mdm_apple_users_push ON mdm_apple_users(next_push_at,id) WHERE status='enrolled';

CREATE TABLE mdm_apple_user_commands (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 user_channel_id UUID NOT NULL,
 request_type TEXT NOT NULL CHECK(request_type IN ('ProfileList','InstallProfile','RemoveProfile')),
 status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','sent','acknowledged','failed','not_now','expired','cancelled')),
 payload BYTEA NOT NULL,
 profile_id UUID,
 profile_revision INTEGER,
 error TEXT NOT NULL DEFAULT '',
 attempts INTEGER NOT NULL DEFAULT 0,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 available_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()+interval '7 days',
 completed_at TIMESTAMPTZ,
 UNIQUE(tenant_id,device_id,user_channel_id,id),
 FOREIGN KEY(tenant_id,device_id,user_channel_id) REFERENCES mdm_apple_users(tenant_id,device_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,profile_id) REFERENCES mdm_apple_profiles(tenant_id,id),
 CHECK((profile_id IS NULL)=(profile_revision IS NULL))
);
CREATE INDEX mdm_apple_user_commands_delivery ON mdm_apple_user_commands(user_channel_id,available_at,created_at) WHERE status IN ('queued','sent','not_now');

CREATE TABLE mdm_apple_user_assignments (
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 user_channel_id UUID NOT NULL,
 profile_id UUID NOT NULL,
 command_id UUID NOT NULL,
 revision INTEGER NOT NULL,
 desired TEXT NOT NULL CHECK(desired IN ('installed','removed')),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','verifying','verified','failed','drifted','not_managed')),
 error TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(user_channel_id,profile_id),
 FOREIGN KEY(tenant_id,device_id,user_channel_id,command_id) REFERENCES mdm_apple_user_commands(tenant_id,device_id,user_channel_id,id),
 FOREIGN KEY(tenant_id,device_id,user_channel_id) REFERENCES mdm_apple_users(tenant_id,device_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,profile_id) REFERENCES mdm_apple_profiles(tenant_id,id)
);

-- User push updates can arrive with a renewal candidate before the device has
-- confirmed that certificate. Preserve the active credentials until promotion.
ALTER TABLE mdm_apple_identity_renewals ADD CONSTRAINT mdm_apple_renewal_channel_scope UNIQUE(tenant_id,device_id,id);
CREATE TABLE mdm_apple_user_renewal_tokens (
 renewal_id UUID NOT NULL,
 tenant_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 user_channel_id UUID NOT NULL,
 encrypted_token BYTEA NOT NULL,
 encrypted_magic BYTEA NOT NULL,
 not_on_console BOOLEAN NOT NULL,
 short_name TEXT NOT NULL DEFAULT '',
 long_name TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(renewal_id,user_channel_id),
 FOREIGN KEY(tenant_id,device_id,renewal_id) REFERENCES mdm_apple_identity_renewals(tenant_id,device_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,device_id,user_channel_id) REFERENCES mdm_apple_users(tenant_id,device_id,id) ON DELETE CASCADE
);
