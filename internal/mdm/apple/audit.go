package apple

import (
	"context"
	"encoding/json"
	"errors"
)

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
