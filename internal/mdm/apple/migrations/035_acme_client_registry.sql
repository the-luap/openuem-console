-- Client ownership survives profile removal, catalog deletion and enrollment
-- deletion. An issuer may treat a client identifier as a one-use credential.
-- A random per-tenant lookup key is encrypted under the existing master key;
-- rewrapping it during master-key rotation preserves the lookup namespace.
CREATE TABLE mdm_apple_acme_registry_keys (
 tenant_id BIGINT PRIMARY KEY REFERENCES tenants(id),
 encrypted_key BYTEA NOT NULL CHECK(octet_length(encrypted_key)=60)
);
CREATE TABLE mdm_apple_acme_clients (
 tenant_id BIGINT NOT NULL REFERENCES tenants(id),
 client_hash TEXT NOT NULL CHECK(client_hash ~ '^[0-9a-f]{64}$'),
 device_id UUID,
 conflicted BOOLEAN NOT NULL DEFAULT false,
 encrypted_client BYTEA NOT NULL CHECK(octet_length(encrypted_client)>28),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,client_hash),
 CHECK((device_id IS NULL)=conflicted)
);

-- Keep gaps in historical evidence explicit. Application migration code indexes
-- retained encrypted revisions without issuing requests to an ACME server.
-- Missing/invalid archives require a reviewed original archive before new ACME
-- assignments in the organization can claim identifiers safely.
CREATE TABLE mdm_apple_acme_legacy_profiles (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id BIGINT NOT NULL REFERENCES tenants(id),
 device_id UUID NOT NULL,
 profile_id UUID NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0),
 profile_revision_id UUID,
 identifier TEXT NOT NULL DEFAULT '',
 payload_scope TEXT NOT NULL CHECK(payload_scope IN ('System','User')),
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','indexed','unresolved','reviewed')),
 reviewed_payload BYTEA,
 reviewed_by TEXT NOT NULL DEFAULT '',
 review_reason TEXT NOT NULL DEFAULT '',
 reviewed_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,device_id,profile_id,revision),
 FOREIGN KEY(tenant_id,profile_id,revision,profile_revision_id)
  REFERENCES mdm_apple_profile_revisions(tenant_id,profile_id,revision,id),
 CHECK((state='reviewed')=(reviewed_payload IS NOT NULL AND octet_length(reviewed_payload)>28
  AND reviewed_by<>'' AND length(review_reason) BETWEEN 1 AND 1000 AND reviewed_at IS NOT NULL))
);
CREATE INDEX mdm_apple_acme_legacy_pending ON mdm_apple_acme_legacy_profiles(tenant_id,id) WHERE state IN ('pending','unresolved');

INSERT INTO mdm_apple_acme_legacy_profiles(tenant_id,device_id,profile_id,revision,profile_revision_id,identifier,payload_scope)
 SELECT a.tenant_id,a.device_id,a.profile_id,a.revision,r.id,COALESCE(r.identifier,p.identifier,''),'System'
 FROM mdm_apple_profile_assignments a
 LEFT JOIN mdm_apple_profile_revisions r ON r.tenant_id=a.tenant_id AND r.profile_id=a.profile_id AND r.revision=a.revision
 LEFT JOIN mdm_apple_profiles p ON p.tenant_id=a.tenant_id AND p.id=a.profile_id
 WHERE r.id IS NULL OR r.payload_types ? 'com.apple.security.acme';
INSERT INTO mdm_apple_acme_legacy_profiles(tenant_id,device_id,profile_id,revision,profile_revision_id,identifier,payload_scope)
 SELECT c.tenant_id,c.device_id,c.profile_id,c.profile_revision,r.id,COALESCE(r.identifier,p.identifier,''),'System'
 FROM mdm_apple_commands c
 LEFT JOIN mdm_apple_profile_revisions r ON r.tenant_id=c.tenant_id AND r.profile_id=c.profile_id AND r.revision=c.profile_revision
 LEFT JOIN mdm_apple_profiles p ON p.tenant_id=c.tenant_id AND p.id=c.profile_id
 WHERE c.request_type='InstallProfile' AND c.attempts>0 AND c.profile_id IS NOT NULL AND c.profile_revision IS NOT NULL
 AND (r.id IS NULL OR r.payload_types ? 'com.apple.security.acme') ON CONFLICT DO NOTHING;
INSERT INTO mdm_apple_acme_legacy_profiles(tenant_id,device_id,profile_id,revision,profile_revision_id,identifier,payload_scope)
 SELECT a.tenant_id,a.device_id,a.profile_id,a.revision,r.id,COALESCE(r.identifier,p.identifier,''),'User'
 FROM mdm_apple_user_assignments a
 LEFT JOIN mdm_apple_profile_revisions r ON r.tenant_id=a.tenant_id AND r.profile_id=a.profile_id AND r.revision=a.revision
 LEFT JOIN mdm_apple_profiles p ON p.tenant_id=a.tenant_id AND p.id=a.profile_id
 WHERE r.id IS NULL OR r.payload_types ? 'com.apple.security.acme' ON CONFLICT DO NOTHING;
INSERT INTO mdm_apple_acme_legacy_profiles(tenant_id,device_id,profile_id,revision,profile_revision_id,identifier,payload_scope)
 SELECT c.tenant_id,c.device_id,c.profile_id,c.profile_revision,r.id,COALESCE(r.identifier,p.identifier,''),'User'
 FROM mdm_apple_user_commands c
 LEFT JOIN mdm_apple_profile_revisions r ON r.tenant_id=c.tenant_id AND r.profile_id=c.profile_id AND r.revision=c.profile_revision
 LEFT JOIN mdm_apple_profiles p ON p.tenant_id=c.tenant_id AND p.id=c.profile_id
 WHERE c.request_type='InstallProfile' AND c.attempts>0 AND c.profile_id IS NOT NULL AND c.profile_revision IS NOT NULL
 AND (r.id IS NULL OR r.payload_types ? 'com.apple.security.acme') ON CONFLICT DO NOTHING;
