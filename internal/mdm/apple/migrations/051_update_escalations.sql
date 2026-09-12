CREATE TABLE mdm_apple_update_escalations (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES tenants(id),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 plan_id UUID NOT NULL,
 assignment_id UUID NOT NULL,
 configuration_revision INTEGER NOT NULL CHECK(configuration_revision>0),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 actor_revision BIGINT NOT NULL CHECK(actor_revision>=0),
 enabled BOOLEAN NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,
 configured_at TIMESTAMPTZ NOT NULL,
 configuration_event_id UUID NOT NULL,
 encrypted_configuration BYTEA NOT NULL CHECK(octet_length(encrypted_configuration) BETWEEN 29 AND 8220),
 state_revision BIGINT NOT NULL CHECK(state_revision>0),
 phase TEXT NOT NULL CHECK(phase IN ('watching','paused','blocked')),
 state_reason TEXT NOT NULL CHECK(state_reason IN ('','authority_changed','source_unavailable')),
 updated_at TIMESTAMPTZ NOT NULL,
 checked_at TIMESTAMPTZ,
 next_check_at TIMESTAMPTZ,
 incident_id UUID,
 acknowledgment_id UUID,
 open_count INTEGER NOT NULL CHECK(open_count BETWEEN 0 AND 100),
 awaiting_count INTEGER NOT NULL CHECK(awaiting_count BETWEEN 0 AND open_count),
 encrypted_state BYTEA NOT NULL CHECK(octet_length(encrypted_state) BETWEEN 29 AND 131100),
 UNIQUE(tenant_id,site_id,assignment_id),
 UNIQUE(id,tenant_id,site_id,plan_id,assignment_id),
 FOREIGN KEY(assignment_id,tenant_id,site_id,plan_id)
  REFERENCES mdm_apple_update_group_assignments(id,tenant_id,site_id,plan_id),
 CHECK((enabled AND phase IN ('watching','blocked')) OR (NOT enabled AND phase='paused')),
 CHECK((phase='watching' AND next_check_at IS NOT NULL) OR (phase<>'watching' AND next_check_at IS NULL)),
 CHECK((open_count=0 AND incident_id IS NULL AND acknowledgment_id IS NULL) OR (open_count>0 AND incident_id IS NOT NULL)),
 CHECK(checked_at IS NOT NULL OR open_count=0)
);
CREATE INDEX mdm_apple_update_escalation_due ON mdm_apple_update_escalations(next_check_at,id) WHERE phase='watching';
CREATE INDEX mdm_apple_update_escalation_site ON mdm_apple_update_escalations(tenant_id,site_id,created_at DESC,id DESC);

CREATE TABLE mdm_apple_update_escalation_events (
 id UUID PRIMARY KEY,
 watch_id UUID NOT NULL,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 plan_id UUID NOT NULL,
 assignment_id UUID NOT NULL,
 revision BIGINT NOT NULL CHECK(revision>0),
 configuration_revision INTEGER NOT NULL CHECK(configuration_revision>0),
 kind TEXT NOT NULL CHECK(kind IN ('configured','attention','updated','cleared','acknowledged','blocked')),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 actor_revision BIGINT NOT NULL CHECK(actor_revision>=0),
 request_key UUID,
 incident_id UUID,
 created_at TIMESTAMPTZ NOT NULL,
 encrypted_event BYTEA NOT NULL CHECK(octet_length(encrypted_event) BETWEEN 29 AND 131100),
 UNIQUE(watch_id,revision),
 UNIQUE(tenant_id,site_id,request_key),
 UNIQUE(id,watch_id,tenant_id,site_id,plan_id,assignment_id),
 FOREIGN KEY(watch_id,tenant_id,site_id,plan_id,assignment_id)
  REFERENCES mdm_apple_update_escalations(id,tenant_id,site_id,plan_id,assignment_id),
 CHECK((kind IN ('configured','acknowledged') AND request_key IS NOT NULL) OR (kind NOT IN ('configured','acknowledged') AND request_key IS NULL))
);
CREATE INDEX mdm_apple_update_escalation_event_history ON mdm_apple_update_escalation_events(tenant_id,site_id,watch_id,revision DESC);
ALTER TABLE mdm_apple_update_escalations
 ADD FOREIGN KEY(configuration_event_id,id,tenant_id,site_id,plan_id,assignment_id)
 REFERENCES mdm_apple_update_escalation_events(id,watch_id,tenant_id,site_id,plan_id,assignment_id) DEFERRABLE INITIALLY DEFERRED,
 ADD FOREIGN KEY(acknowledgment_id,id,tenant_id,site_id,plan_id,assignment_id)
 REFERENCES mdm_apple_update_escalation_events(id,watch_id,tenant_id,site_id,plan_id,assignment_id) DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION mdm_apple_keep_update_escalation_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'Original Apple update escalation events are immutable';
END;
$$;
CREATE TRIGGER mdm_apple_keep_update_escalation_event BEFORE UPDATE OR DELETE
 ON mdm_apple_update_escalation_events FOR EACH ROW EXECUTE FUNCTION mdm_apple_keep_update_escalation_event();
