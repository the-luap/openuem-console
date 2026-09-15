-- Historical versions outlive the mutable catalog entry. The migration can
-- retain only the current existing payload; it does not invent earlier versions.
CREATE TABLE mdm_apple_profile_revisions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id BIGINT NOT NULL REFERENCES tenants(id),
 profile_id UUID NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0),
 name TEXT NOT NULL,
 identifier TEXT NOT NULL,
 payload_uuid TEXT NOT NULL,
 payload_scope TEXT NOT NULL CHECK(payload_scope IN ('System','User')),
 payload_types JSONB NOT NULL CHECK(jsonb_typeof(payload_types)='array'),
 encrypted_payload BYTEA NOT NULL CHECK(octet_length(encrypted_payload)>28),
 encryption_kind TEXT NOT NULL CHECK(encryption_kind IN ('profile','revision')),
 origin TEXT NOT NULL CHECK(origin IN ('migration','save','restore')),
 actor TEXT NOT NULL DEFAULT '',
 reason TEXT NOT NULL DEFAULT '' CHECK(length(reason)<=1000),
 restored_from UUID,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK((origin='migration' AND encryption_kind='profile' AND actor='' AND restored_from IS NULL)
    OR (origin='save' AND encryption_kind='revision' AND actor<>'' AND restored_from IS NULL)
    OR (origin='restore' AND encryption_kind='revision' AND actor<>'' AND restored_from IS NOT NULL AND length(reason)>0)),
 UNIQUE(tenant_id,profile_id,revision),
 UNIQUE(tenant_id,profile_id,id),
 UNIQUE(tenant_id,profile_id,payload_uuid),
 UNIQUE(tenant_id,profile_id,revision,payload_uuid,id),
 FOREIGN KEY(tenant_id,profile_id,restored_from) REFERENCES mdm_apple_profile_revisions(tenant_id,profile_id,id)
);
INSERT INTO mdm_apple_profile_revisions(tenant_id,profile_id,revision,name,identifier,payload_uuid,payload_scope,payload_types,encrypted_payload,encryption_kind,origin)
 SELECT tenant_id,id,revision,name,identifier,payload_uuid,payload_scope,payload_types,payload,'profile','migration' FROM mdm_apple_profiles;
CREATE INDEX mdm_apple_profile_revision_history ON mdm_apple_profile_revisions(tenant_id,created_at DESC,id DESC);
CREATE INDEX mdm_apple_profile_revision_family ON mdm_apple_profile_revisions(tenant_id,profile_id,created_at DESC,id DESC);
CREATE FUNCTION mdm_apple_profile_revision_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'Profile revision snapshots are immutable';
END;
$$;
CREATE TRIGGER mdm_apple_profile_revision_immutable BEFORE UPDATE OR DELETE ON mdm_apple_profile_revisions
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_profile_revision_immutable();

ALTER TABLE mdm_apple_profiles ADD COLUMN revision_id UUID;
UPDATE mdm_apple_profiles p SET revision_id=r.id FROM mdm_apple_profile_revisions r
 WHERE r.tenant_id=p.tenant_id AND r.profile_id=p.id AND r.revision=p.revision;
ALTER TABLE mdm_apple_profiles ALTER COLUMN revision_id SET NOT NULL;
ALTER TABLE mdm_apple_profiles ADD CONSTRAINT mdm_apple_profile_current_revision
 FOREIGN KEY(tenant_id,id,revision,payload_uuid,revision_id)
 REFERENCES mdm_apple_profile_revisions(tenant_id,profile_id,revision,payload_uuid,id);
