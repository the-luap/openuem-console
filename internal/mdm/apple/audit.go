package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// Capture site attribution at the time of the action. Historical rows without
// this metadata remain organization-wide; readers do not guess it from current
// device placement or accept arbitrary payload fields as outcomes.
func auditOutcome(ctx context.Context, tx *sql.Tx, tenant int, actor, action, resource, result string) error {
	switch result {
	case "success", "failure", "denied", "deferred", "cancelled":
	default:
		return errors.New("invalid audit outcome")
	}
	site := 0
	query, target := "", resource
	switch {
	case action == "apple.mac.binding.request" || action == "apple.mac.channels.conflict":
		query = `SELECT site_id FROM mdm_apple_mac_bindings WHERE tenant_id=$1 AND id::text=$2`
	case action == "apple.mac.binding.cancel" || action == "apple.mac.binding.cleanup.request":
		query = `SELECT site_id FROM mdm_apple_devices WHERE tenant_id=$1 AND id::text=$2`
	case action == "apple.mac.channels.link":
		query = `SELECT site_id FROM uem_mac_devices WHERE tenant_id=$1 AND id::text=$2`
	case strings.HasPrefix(action, "apple.identity.renewal."):
		query = `SELECT d.site_id FROM mdm_apple_identity_renewals r JOIN mdm_apple_devices d ON d.id=r.device_id AND d.tenant_id=r.tenant_id WHERE r.tenant_id=$1 AND r.id::text=$2`
	case strings.HasPrefix(action, "apple.command."):
		query = `SELECT d.site_id FROM mdm_apple_commands c JOIN mdm_apple_devices d ON d.id=c.device_id AND d.tenant_id=c.tenant_id WHERE c.tenant_id=$1 AND c.id::text=$2`
	case strings.HasPrefix(action, "apple.enrollment."), strings.HasPrefix(action, "apple.checkin."), strings.HasPrefix(action, "apple.bootstrap_token."), action == "apple.inventory.refresh", action == "apple.update.policy", action == "apple.identity.layout.recover", action == "apple.scep.enrollment.issue":
		query = `SELECT site_id FROM mdm_apple_devices WHERE tenant_id=$1 AND id::text=$2`
	case action == "apple.profile.installed" || action == "apple.profile.removed":
		parts := strings.Split(resource, "/")
		if len(parts) == 2 {
			target = parts[1]
			query = `SELECT site_id FROM mdm_apple_devices WHERE tenant_id=$1 AND id::text=$2`
		}
	}
	if query != "" {
		err := tx.QueryRowContext(ctx, query, tenant, target).Scan(&site)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	details, err := json.Marshal(map[string]any{"site_id": site, "result": result})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,details) VALUES($1,$2,$3,$4,$5)`, tenant, actor, action, resource, details)
	return err
}

// RecordRead records successful inventory/profile access before returning data.
// It stores scope and resource identifiers, never credentials or profile contents.
func (s *Store) RecordRead(ctx context.Context, scope Scope, actor, action, resource string) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if actor == "" || resource == "" {
		return errors.New("read audit requires an actor and resource")
	}
	switch action {
	case "inventory.list", "inventory.read", "profile.download":
	default:
		return errors.New("unsupported read audit action")
	}
	details, err := json.Marshal(map[string]any{"site_id": scope.SiteID, "result": "success"})
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,details) VALUES($1,$2,$3,$4,$5)`, scope.TenantID, actor, action, resource, details)
	return err
}
