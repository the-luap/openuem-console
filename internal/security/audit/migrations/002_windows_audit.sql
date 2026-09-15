-- Existing retention policies never acquire Windows deletion authority on upgrade.
ALTER TABLE uem_audit_retention ADD COLUMN windows_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE uem_audit_retention ADD CONSTRAINT uem_audit_windows_organization CHECK (NOT windows_enabled OR tenant_id>0);
ALTER TABLE uem_audit_retention_previews ADD COLUMN windows_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE uem_audit_retention_previews ADD CONSTRAINT uem_audit_windows_preview_organization CHECK (NOT windows_enabled OR tenant_id>0);
ALTER TABLE uem_audit_retention_history ADD COLUMN windows_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE uem_audit_retention_history ADD COLUMN previous_windows_enabled BOOLEAN;

-- A committed batch records only source event IDs, never payloads or credentials.
-- The transaction ID prevents a later operation from reusing deletion authority.
CREATE TABLE uem_audit_windows_batches (
    receipt_id BIGINT PRIMARY KEY REFERENCES uem_audit_retention_history(id) ON DELETE RESTRICT,
    transaction_id BIGINT NOT NULL DEFAULT txid_current(),
    table_oid OID NOT NULL,
    source TEXT NOT NULL,
    tenant_id BIGINT NOT NULL CHECK(tenant_id>0),
    policy_revision BIGINT NOT NULL CHECK(policy_revision>0),
    cutoff TIMESTAMPTZ NOT NULL,
    event_ids JSONB NOT NULL CHECK(jsonb_typeof(event_ids)='array' AND jsonb_array_length(event_ids) BETWEEN 1 AND 1000),
    UNIQUE(transaction_id,table_oid)
);

CREATE FUNCTION uem_audit_keep_windows_batch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Windows audit deletion receipts are immutable';
END;
$$;
CREATE TRIGGER uem_audit_windows_batch_history BEFORE UPDATE OR DELETE ON uem_audit_windows_batches
    FOR EACH ROW EXECUTE FUNCTION uem_audit_keep_windows_batch();

CREATE FUNCTION uem_audit_guard_windows_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM uem_audit_windows_batches WHERE receipt_id=OLD.id) THEN
        RAISE EXCEPTION 'Windows audit deletion receipts are immutable';
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER uem_audit_windows_receipt_history BEFORE UPDATE OR DELETE ON uem_audit_retention_history
    FOR EACH ROW EXECUTE FUNCTION uem_audit_guard_windows_receipt();

CREATE FUNCTION uem_audit_guard_windows_history() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    actual_tenant BIGINT;
BEGIN
    IF TG_OP='DELETE' THEN
        actual_tenant := (to_jsonb(OLD)->>'tenant_id')::bigint;
        IF TG_ARGV[0]='windows_updates' THEN
            SELECT tenant_id INTO actual_tenant FROM mdm_windows_update_runs WHERE id=OLD.run_id;
        ELSIF TG_ARGV[0]='windows_disconnection_requests' THEN
            SELECT tenant_id INTO actual_tenant FROM mdm_windows_unenrollment_requests WHERE id=OLD.request_id;
        ELSIF TG_ARGV[0]='windows_certificate_reminders' THEN
            SELECT tenant_id INTO actual_tenant FROM mdm_windows_certificate_reminders WHERE id=OLD.reminder_id;
        END IF;
        IF EXISTS (
            SELECT 1 FROM uem_audit_windows_batches b
            JOIN uem_audit_retention p ON p.tenant_id=b.tenant_id
            JOIN uem_audit_retention_history r ON r.id=b.receipt_id
            WHERE b.transaction_id=txid_current() AND b.table_oid=TG_RELID AND b.source=TG_ARGV[0]
              AND b.tenant_id=actual_tenant AND b.event_ids @> jsonb_build_array(OLD.id)
              AND OLD.created_at<b.cutoff AND b.cutoff<=clock_timestamp()-p.days*interval '1 day'
              AND p.windows_enabled AND p.days>0 AND p.revision=b.policy_revision
              AND r.action='retention.prune' AND r.actor='retention-service'
              AND r.tenant_id=b.tenant_id AND r.revision=b.policy_revision AND r.days=p.days
              AND r.source=b.source AND r.cutoff=b.cutoff AND r.windows_enabled
              AND r.event_count=jsonb_array_length(b.event_ids)
        ) THEN RETURN OLD; END IF;
    END IF;
    RAISE EXCEPTION 'Windows audit history requires a scoped retention receipt for deletion';
END;
$$;
