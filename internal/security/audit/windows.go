package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Each Windows source has a distinct cursor namespace. Joins use immutable
// enrollment/run scope, never the device's current placement or reported names.
var windowsSources = []auditSource{
	{"windows_enrollment", "mdm_windows_audit", `SELECT id,tenant_id,site_id,actor,action,resource_id::text AS resource,'recorded'::text AS result,created_at FROM mdm_windows_audit`},
	{"windows_authority", "mdm_windows_authority_audit", `SELECT id,tenant_id,0::bigint AS site_id,actor,action,authority_id::text AS resource,'recorded'::text AS result,created_at FROM mdm_windows_authority_audit`},
	{"windows_management", "mdm_windows_management_audit", `SELECT id,tenant_id,site_id,'windows-device'::text AS actor,action,session_id::text AS resource,'recorded'::text AS result,created_at FROM mdm_windows_management_audit`},
	{"windows_csp", "mdm_windows_csp_audit", `SELECT id,tenant_id,site_id,actor,action,command_id::text AS resource,'recorded'::text AS result,created_at FROM mdm_windows_csp_audit`},
	{"windows_updates", "mdm_windows_update_audit", `SELECT a.id,r.tenant_id,r.site_id,a.actor,a.action,a.run_id::text AS resource,'recorded'::text AS result,a.created_at FROM mdm_windows_update_audit a JOIN mdm_windows_update_runs r ON r.id=a.run_id`},
	{"windows_rings", "mdm_windows_update_ring_audit", `SELECT id,tenant_id,site_id,actor,action,COALESCE(rollout_id,ring_id)::text AS resource,'recorded'::text AS result,created_at FROM mdm_windows_update_ring_audit`},
	{"windows_schedules", "mdm_windows_update_schedule_audit", `SELECT id,tenant_id,site_id,actor,action,schedule_id::text AS resource,'recorded'::text AS result,created_at FROM mdm_windows_update_schedule_audit`},
	{"windows_console", "mdm_windows_console_audit", `SELECT id,tenant_id,site_id,actor,action,COALESCE(resource_id::text,'organization:'||tenant_id::text) AS resource,'recorded'::text AS result,created_at FROM mdm_windows_console_audit`},
	{"windows_renewal", "mdm_windows_renewal_audit", `SELECT id,tenant_id,site_id,actor,action,renewal_id::text AS resource,'recorded'::text AS result,created_at FROM mdm_windows_renewal_audit`},
	{"windows_unenrollment", "mdm_windows_unenrollment_audit", `SELECT id,tenant_id,site_id,actor,action,report_id::text AS resource,'recorded'::text AS result,created_at FROM mdm_windows_unenrollment_audit`},
	{"windows_disconnection_requests", "mdm_windows_unenrollment_request_audit", `SELECT a.id,r.tenant_id,r.site_id,a.actor,a.action,a.request_id::text AS resource,'recorded'::text AS result,a.created_at FROM mdm_windows_unenrollment_request_audit a JOIN mdm_windows_unenrollment_requests r ON r.id=a.request_id`},
	{"windows_certificate_reminders", "mdm_windows_certificate_reminder_audit", `SELECT a.id,r.tenant_id,r.site_id,a.actor,a.action,COALESCE(a.delivery_id,a.reminder_id)::text AS resource,'recorded'::text AS result,a.created_at FROM mdm_windows_certificate_reminder_audit a JOIN mdm_windows_certificate_reminders r ON r.id=a.reminder_id`},
}

func isWindowsSource(source string) bool {
	return strings.HasPrefix(source, "windows_") && validSource(source)
}

// SourceNames returns a copy, including optional sources not yet installed.
func SourceNames() []string {
	names := make([]string, 0, len(sourceQueries))
	for _, source := range sourceQueries {
		names = append(names, source.name)
	}
	return names
}

func SourceLabel(name string) string {
	switch name {
	case "windows_enrollment":
		return "Windows enrollment"
	case "windows_authority":
		return "Windows certificate authorities"
	case "windows_management":
		return "Windows management sessions"
	case "windows_csp":
		return "Windows CSP commands"
	case "windows_updates":
		return "Windows update policies"
	case "windows_rings":
		return "Windows update rings"
	case "windows_schedules":
		return "Windows update schedules"
	case "windows_console":
		return "Windows console access"
	case "windows_renewal":
		return "Windows certificate renewal"
	case "windows_unenrollment":
		return "Windows disconnection reports"
	case "windows_disconnection_requests":
		return "Windows disconnection requests"
	case "windows_certificate_reminders":
		return "Windows certificate reminders"
	default:
		return strings.Title(name)
	}
}

// installWindowsAuditGuard changes only known audit-row guards. Command,
// enrollment, packet and observation immutability remains with Windows storage.
func installWindowsAuditGuard(ctx context.Context, tx *sql.Tx, source auditSource) error {
	oldTrigger := map[string]string{
		"windows_management":             "mdm_windows_management_audit_history",
		"windows_csp":                    "mdm_windows_csp_audit_history",
		"windows_updates":                "mdm_windows_update_audit_history",
		"windows_rings":                  "mdm_windows_update_ring_audit_history",
		"windows_schedules":              "mdm_windows_update_schedule_audit_history",
		"windows_console":                "mdm_windows_console_audit_immutable",
		"windows_renewal":                "mdm_windows_renewal_audit_history",
		"windows_unenrollment":           "mdm_windows_unenrollment_audit_history",
		"windows_disconnection_requests": "mdm_windows_unenrollment_request_audit_history",
		"windows_certificate_reminders":  "mdm_windows_certificate_reminder_audit_history",
	}[source.name]
	if oldTrigger != "" {
		if _, err := tx.ExecContext(ctx, `DROP TRIGGER IF EXISTS `+oldTrigger+` ON `+source.table); err != nil {
			return err
		}
	}
	// Idempotent source registration also repairs optional tables introduced
	// after the audit schema was first installed, before they can be pruned.
	if _, err := tx.ExecContext(ctx, `DROP TRIGGER IF EXISTS uem_audit_windows_history ON `+source.table); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `CREATE TRIGGER uem_audit_windows_history BEFORE UPDATE OR DELETE ON `+source.table+` FOR EACH ROW EXECUTE FUNCTION uem_audit_guard_windows_history('`+source.name+`')`)
	return err
}

// pruneWindowsAudit binds the exact selected IDs to an immutable receipt in this
// transaction. The row trigger independently checks scope, policy, age and IDs.
func pruneWindowsAudit(ctx context.Context, tx *sql.Tx, policy RetentionPolicy, source retentionSource, cutoff time.Time) (int, error) {
	var guarded bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=$1::regclass AND tgname='uem_audit_windows_history' AND tgfoid='uem_audit_guard_windows_history()'::regprocedure AND tgenabled='O' AND NOT tgisinternal)`, source.table).Scan(&guarded); err != nil {
		return 0, err
	}
	if !guarded {
		return 0, errors.New("Windows audit retention guard is unavailable")
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.id FROM `+source.table+` a JOIN (`+source.query+`) e ON e.id=a.id WHERE e.tenant_id=$1 AND a.created_at<$2 ORDER BY a.created_at,a.id LIMIT 1000 FOR UPDATE OF a SKIP LOCKED`, policy.TenantID, cutoff)
	if err != nil {
		return 0, err
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	var receipt int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO uem_audit_retention_history(tenant_id,actor,action,days,revision,source,cutoff,event_count,windows_enabled) VALUES($1,'retention-service','retention.prune',$2,$3,$4,$5,$6,true) RETURNING id`, policy.TenantID, policy.Days, policy.Revision, source.name, cutoff, len(ids)).Scan(&receipt); err != nil {
		return 0, err
	}
	encoded, err := json.Marshal(ids)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO uem_audit_windows_batches(receipt_id,table_oid,source,tenant_id,policy_revision,cutoff,event_ids) VALUES($1,$2::regclass::oid,$3,$4,$5,$6,$7::jsonb)`, receipt, source.table, source.name, policy.TenantID, policy.Revision, cutoff, string(encoded)); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM `+source.table+` WHERE id IN (SELECT value::bigint FROM jsonb_array_elements_text($1::jsonb))`, string(encoded))
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if count != int64(len(ids)) {
		return 0, errors.New("Windows audit retention receipt count mismatch")
	}
	return int(count), nil
}
