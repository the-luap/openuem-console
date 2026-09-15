package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/nats/tasksecrets"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/taskconfig"
)

var ErrTaskEditConflict = errors.New("task configuration changed or cannot be edited")

type TaskEditReview struct {
	ProfileID     int64
	Task          *ent.Task
	PasswordSet   bool
	PassphraseSet bool
}

func ReviewTaskEdit(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, taskID int64) (*TaskEditReview, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, profileID, err := beginLegacyTaskTransaction(ctx, db, permissions, actor, scope, taskID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var bounded bool
	// Reject oversized legacy configuration instead of silently truncating values
	// that would later be saved. Secret values never leave this SQL operation.
	err = tx.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM jsonb_each_text(to_jsonb(t)) v WHERE v.key NOT IN ('local_user_password','local_user_ssh_key_passphrase') AND octet_length(v.value)>CASE WHEN v.key='name' THEN 2048 WHEN v.key='script' THEN 131072 ELSE 16384 END) FROM tasks t WHERE id=$1 AND profile_tasks=$2`, taskID, profileID).Scan(&bounded)
	if err != nil {
		return nil, err
	}
	if !bounded {
		return nil, ErrTaskEditConflict
	}
	columns := make([]string, 0, len(task.Columns))
	for _, column := range task.Columns {
		if column != task.FieldLocalUserPassword && column != task.FieldLocalUserSSHKeyPassphrase {
			columns = append(columns, column)
		}
	}
	client := ent.NewClient(ent.Driver(entsql.NewDriver(dialect.Postgres, entsql.Conn{ExecQuerier: tx})))
	current, err := client.Task.Query().Where(task.ID(int(taskID))).Select(columns...).Only(ctx)
	if err != nil {
		return nil, err
	}
	if !(taskconfig.Config{TaskType: current.Type.String(), AgentsType: current.AgentType.String()}).Supported() || current.Version < 0 || current.Version >= 2147483647 {
		return nil, ErrTaskEditConflict
	}
	if current.Type == task.TypeNetbirdRegister && (scope.TenantID == 0 || current.Tenant != scope.TenantID) {
		return nil, ErrProfileCloneProviderScope
	}
	review := &TaskEditReview{ProfileID: profileID, Task: current}
	err = tx.QueryRowContext(ctx, `SELECT coalesce(local_user_password<>'',false),coalesce(local_user_ssh_key_passphrase<>'',false) FROM tasks WHERE id=$1 AND profile_tasks=$2`, taskID, profileID).Scan(&review.PasswordSet, &review.PassphraseSet)
	if err != nil {
		return nil, err
	}
	resource := fmt.Sprintf("%d/profile/%d/version/%d", taskID, profileID, current.Version)
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.tasks.edit_review',$4)`, scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return review, nil
}

// Secret choices are explicit so that an empty rendered input never erases a
// stored password or passphrase accidentally.
type TaskEditSecrets struct {
	PasswordAction   string
	PassphraseAction string
}

func editSecretValue(action, value string) (*string, error) {
	switch action {
	case "keep":
		if value == "" {
			return nil, nil
		}
	case "clear":
		if value == "" {
			return &value, nil
		}
	case "replace":
		if value != "" {
			return &value, nil
		}
	}
	return nil, ErrTaskInvalid
}

func UpdateLegacyTask(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, taskID, expectedProfile int64, expectedVersion int, cfg taskconfig.Config, choices TaskEditSecrets, masterKey string) (int, error) {
	if expectedProfile <= 0 || expectedVersion < 0 || expectedVersion >= 2147483647 || !cfg.Supported() || !(ProfileMetadata{Name: cfg.Description, Assignment: "dontApplyToAll"}).Valid() {
		return 0, ErrTaskInvalid
	}
	password, err := editSecretValue(choices.PasswordAction, cfg.LocalUserPassword)
	if err != nil {
		return 0, err
	}
	passphrase, err := editSecretValue(choices.PassphraseAction, cfg.LocalUserSSHKeyPassphrase)
	if err != nil {
		return 0, err
	}
	if password != nil && cfg.TaskType != task.TypeAddLocalUser.String() && cfg.TaskType != task.TypeAddUnixLocalUser.String() {
		return 0, ErrTaskInvalid
	}
	if passphrase != nil && cfg.TaskType != task.TypeAddUnixLocalUser.String() {
		return 0, ErrTaskInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, profileID, err := beginLegacyTaskTransaction(ctx, db, permissions, actor, scope, taskID)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if profileID != expectedProfile {
		return 0, ErrNotFound
	}
	var currentType, platform string
	var version, providerTenant int
	err = tx.QueryRowContext(ctx, `SELECT type,agent_type,coalesce(version,0),coalesce(tenant,0) FROM tasks WHERE id=$1 AND profile_tasks=$2`, taskID, profileID).Scan(&currentType, &platform, &version, &providerTenant)
	if err != nil {
		return 0, err
	}
	if version != expectedVersion {
		return 0, ErrTaskEditConflict
	}
	if currentType != cfg.TaskType || platform != cfg.AgentsType {
		return 0, ErrTaskInvalid
	}
	if currentType == task.TypeNetbirdRegister.String() && (scope.TenantID == 0 || providerTenant != scope.TenantID) {
		return 0, ErrProfileCloneProviderScope
	}
	if password != nil && *password != "" {
		if masterKey == "" {
			return 0, ErrTaskSecretStorage
		}
		encrypted, err := tasksecrets.SealPassword(*password, masterKey)
		if err != nil {
			return 0, ErrTaskSecretStorage
		}
		password = &encrypted
	}
	if passphrase != nil && *passphrase != "" {
		encrypted, err := tasksecrets.SealSSH(*passphrase, masterKey)
		if err != nil {
			return 0, ErrTaskSecretStorage
		}
		passphrase = &encrypted
	}
	client := ent.NewClient(ent.Driver(entsql.NewDriver(dialect.Postgres, entsql.Conn{ExecQuerier: tx})))
	next := version + 1
	count, err := taskconfig.Update(ctx, client, int(taskID), int(profileID), next, cfg, taskconfig.SecretUpdate{Password: password, SSHKeyPassphrase: passphrase})
	if err != nil {
		if errors.Is(err, taskconfig.ErrInvalid) || ent.IsValidationError(err) {
			return 0, ErrTaskInvalid
		}
		return 0, err
	}
	if count != 1 {
		return 0, ErrNotFound
	}
	resource := fmt.Sprintf("%d/profile/%d/version/%d", taskID, profileID, next)
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.tasks.update',$4)`, scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}
