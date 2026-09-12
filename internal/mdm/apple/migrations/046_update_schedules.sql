CREATE TABLE mdm_apple_update_schedules (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL REFERENCES tenants(id),
 site_id BIGINT NOT NULL CHECK(site_id>0),
 request_key UUID NOT NULL,
 plan_id UUID NOT NULL,
 plan_revision INTEGER NOT NULL CHECK(plan_revision>0),
 actor TEXT NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 255),
 actor_revision BIGINT NOT NULL CHECK(actor_revision>=0),
 created_at TIMESTAMPTZ NOT NULL,
 not_before TIMESTAMPTZ NOT NULL CHECK(not_before>=created_at-INTERVAL '1 minute' AND not_before<=created_at+INTERVAL '90 days'),
 expires_at TIMESTAMPTZ NOT NULL CHECK(expires_at>created_at AND expires_at>=not_before+INTERVAL '1 minute' AND expires_at<=not_before+INTERVAL '7 days'),
 encrypted_intent BYTEA NOT NULL CHECK(octet_length(encrypted_intent) BETWEEN 29 AND 32796),
 phase TEXT NOT NULL CHECK(phase IN ('scheduled','waiting','activated','blocked','canceled','expired')),
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 updated_at TIMESTAMPTZ NOT NULL CHECK(updated_at>=created_at),
 next_attempt_at TIMESTAMPTZ NOT NULL CHECK(next_attempt_at>=not_before),
 attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 20000),
 completed_at TIMESTAMPTZ CHECK(completed_at=updated_at),
 assignment_id UUID UNIQUE REFERENCES mdm_apple_update_group_assignments(id),
 encrypted_state BYTEA NOT NULL CHECK(octet_length(encrypted_state) BETWEEN 29 AND 1052),
 CHECK((phase IN ('scheduled','waiting'))=(completed_at IS NULL)),
 CHECK((phase='activated')=(assignment_id IS NOT NULL)),
 CHECK(phase<>'activated' OR (completed_at>=not_before AND completed_at<expires_at)),
 CHECK(phase<>'scheduled' OR (revision=1 AND attempts=0 AND updated_at=created_at AND next_attempt_at=not_before)),
 UNIQUE(tenant_id,site_id,request_key),
 FOREIGN KEY(plan_id,tenant_id,site_id) REFERENCES mdm_apple_update_plans(id,tenant_id,site_id),
 FOREIGN KEY(plan_id,plan_revision) REFERENCES mdm_apple_update_plan_revisions(plan_id,revision)
);
CREATE INDEX mdm_apple_update_schedule_due ON mdm_apple_update_schedules
 (LEAST(next_attempt_at,expires_at),id) WHERE phase IN ('scheduled','waiting');
CREATE INDEX mdm_apple_update_schedule_history ON mdm_apple_update_schedules
 (tenant_id,site_id,plan_id,created_at DESC,id DESC);
CREATE FUNCTION mdm_apple_keep_update_schedule() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR
 ROW(NEW.id,NEW.tenant_id,NEW.site_id,NEW.request_key,NEW.plan_id,NEW.plan_revision,NEW.actor,NEW.actor_revision,NEW.created_at,NEW.not_before,NEW.expires_at,NEW.encrypted_intent)
 IS DISTINCT FROM
 ROW(OLD.id,OLD.tenant_id,OLD.site_id,OLD.request_key,OLD.plan_id,OLD.plan_revision,OLD.actor,OLD.actor_revision,OLD.created_at,OLD.not_before,OLD.expires_at,OLD.encrypted_intent)
 OR OLD.phase NOT IN ('scheduled','waiting') OR NEW.phase NOT IN ('waiting','activated','blocked','canceled','expired')
 OR NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at OR NEW.next_attempt_at<OLD.next_attempt_at
 OR NEW.attempts<OLD.attempts OR NEW.attempts>OLD.attempts+1
 THEN RAISE EXCEPTION 'Apple update schedule identity and progression are protected'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER mdm_apple_update_schedule_identity BEFORE UPDATE OR DELETE ON mdm_apple_update_schedules
 FOR EACH ROW EXECUTE FUNCTION mdm_apple_keep_update_schedule();
