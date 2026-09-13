package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/open-uem/nats"
	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/taskconfig"
)

var ErrTaskWizardProvider = errors.New("task provider groups are unavailable")

type TaskWizardGroupReader func(context.Context, string, string) ([]nats.NetBirdGroups, error)

// ReadTaskWizard holds current authority, destination scope and configured
// provider settings through lookup and audit commit. It never creates settings
// or selects existing task definitions, scripts or task credentials.
func ReadTaskWizard(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID int64, stage, value, masterKey string, readGroups TaskWizardGroupReader) ([]nats.NetBirdGroups, error) {
	if !taskconfig.WizardValue(stage, value) {
		return nil, ErrTaskInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileTransaction(ctx, db, permissions, actor, scope, profileID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	groups := []nats.NetBirdGroups{}
	if stage == "definition" && value == "netbird_register" {
		if scope.TenantID == 0 {
			return nil, ErrProfileCloneProviderScope
		}
		if readGroups == nil {
			return nil, ErrTaskWizardProvider
		}
		var base, token string
		// The scope transaction already holds the tenant row, including its settings
		// FK. Lock the referenced settings row against rotation until the read ends.
		err = tx.QueryRowContext(ctx, `SELECT coalesce(n.management_url,''),coalesce(n.access_token,'') FROM netbird_settings n JOIN tenants t ON t.tenant_netbird=n.id WHERE t.id=$1 AND coalesce(octet_length(n.management_url),0)<=2048 AND coalesce(octet_length(n.access_token),0)<=$2 FOR SHARE OF n`, scope.TenantID, legacysecret.MaxStoredSize).Scan(&base, &token)
		if err != nil || token == "" {
			return nil, ErrTaskWizardProvider
		}
		token, err = legacysecret.Open(token, masterKey)
		if err != nil || token == "" {
			return nil, ErrTaskWizardProvider
		}

		lookupCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		groups, err = readGroups(lookupCtx, base, token)
		stop()
		if err != nil {
			return nil, ErrTaskWizardProvider
		}
	}
	resource := fmt.Sprintf("%d/stage/%s", profileID, stage)
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.tasks.wizard_read',$4)`, scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return groups, nil
}
