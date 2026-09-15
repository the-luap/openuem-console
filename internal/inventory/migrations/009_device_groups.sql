CREATE TABLE uem_device_groups (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL CHECK(tenant_id>0),
 site_id BIGINT NOT NULL CHECK(site_id>=0),
 revision INTEGER NOT NULL CHECK(revision>0)
);
CREATE INDEX uem_device_groups_scope ON uem_device_groups(tenant_id,site_id,id);
CREATE TABLE uem_device_group_revisions (
 group_id UUID NOT NULL REFERENCES uem_device_groups(id),
 revision INTEGER NOT NULL CHECK(revision>0),
 name TEXT NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 120),
 description TEXT NOT NULL CHECK(octet_length(description)<=1024),
 platform TEXT NOT NULL CHECK(platform IN ('','apple','ios','ipados','macos','windows','linux','unknown')),
 search TEXT NOT NULL CHECK(octet_length(search)<=256),
 archived BOOLEAN NOT NULL,
 actor TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(group_id,revision)
);
ALTER TABLE uem_device_groups ADD CONSTRAINT uem_device_groups_current_revision
 FOREIGN KEY(id,revision) REFERENCES uem_device_group_revisions(group_id,revision) DEFERRABLE INITIALLY DEFERRED;
