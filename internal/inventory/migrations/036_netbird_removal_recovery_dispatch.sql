-- A pre-delivery dispatch stop retains the device barrier until explicit cancel.
CREATE TABLE uem_netbird_removal_recovery_dispatch_stops (
 request_id UUID PRIMARY KEY REFERENCES uem_netbird_removal_recoveries(id),
 reason TEXT NOT NULL CHECK(reason IN ('expired','not_authorized','source_changed')),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION uem_netbird_removal_recovery_dispatch_stop_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NetBird recovery dispatch stops are permanent'; END $$;
CREATE TRIGGER uem_netbird_removal_recovery_dispatch_stop_immutable BEFORE UPDATE OR DELETE ON uem_netbird_removal_recovery_dispatch_stops FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_recovery_dispatch_stop_immutable();
CREATE FUNCTION uem_netbird_removal_recovery_dispatch_stop_valid() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r uem_netbird_removal_recoveries%ROWTYPE;
BEGIN
 SELECT * INTO r FROM uem_netbird_removal_recoveries WHERE id=NEW.request_id FOR UPDATE;
 IF NOT FOUND OR r.cancelled_at IS NOT NULL OR r.completed_at IS NOT NULL OR r.released_at IS NOT NULL
  OR EXISTS(SELECT 1 FROM uem_netbird_removal_recovery_attempts WHERE request_id=r.id)
  OR NEW.recorded_at<r.requested_at OR NEW.recorded_at>clock_timestamp()+interval '5 seconds'
 THEN RAISE EXCEPTION 'NetBird recovery cannot stop before delivery'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_recovery_dispatch_stop_valid BEFORE INSERT ON uem_netbird_removal_recovery_dispatch_stops FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_recovery_dispatch_stop_valid();
CREATE FUNCTION uem_netbird_removal_recovery_dispatch_required() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM 1 FROM uem_netbird_removal_recoveries WHERE id=NEW.request_id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM uem_netbird_removal_recovery_dispatch_stops WHERE request_id=NEW.request_id)
 THEN RAISE EXCEPTION 'NetBird recovery dispatch was stopped'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER uem_netbird_removal_recovery_dispatch_required BEFORE INSERT ON uem_netbird_removal_recovery_attempts FOR EACH ROW EXECUTE FUNCTION uem_netbird_removal_recovery_dispatch_required();
