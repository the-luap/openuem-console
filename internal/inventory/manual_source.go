package inventory

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/taskconfig"
	"github.com/open-uem/openuem-console/internal/taskexecution"
)

type ManualTarget struct {
	ID, Name, Platform string
	Scope              access.Scope
}

type ManualSource struct {
	Kind, Name, ProfileName, Type, Revision string
	ID, ProfileID                           int64
	Version, TaskCount                      int
	Scope                                   access.Scope
}

type ManualReview struct {
	Target ManualTarget
	Source ManualSource
}

type manualLockedSource struct {
	source ManualSource
	task   *ent.Task
}

func (s *ManualExecutionStore) beginRecord(ctx context.Context, actor string, scope access.Scope) (*sql.Tx, error) {
	if scope.TenantID <= 0 || scope.SiteID <= 0 {
		return nil, ErrManualInvalid
	}
	tx, err := beginGroupTransaction(ctx, s.db, s.permissions, actor, scope, access.ManageProfiles)
	if err != nil {
		return nil, err
	}
	if err = s.permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageProfiles, access.Scope{}); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func (s *ManualExecutionStore) target(ctx context.Context, tx *sql.Tx, scope access.Scope, deviceID string) (ManualTarget, error) {
	var target ManualTarget
	if !ValidReportDeviceID(deviceID) {
		return target, ErrManualInvalid
	}
	refresh := &RefreshStore{db: s.db, permissions: s.permissions, individual: s.individual}
	actual, err := refresh.target(ctx, tx, scope, deviceID)
	if err != nil {
		return target, err
	}
	target = ManualTarget{ID: deviceID, Scope: actual}
	if err = tx.QueryRowContext(ctx, "SELECT coalesce(left(nullif(nickname,''),256),left(hostname,256),''),coalesce(os,'') FROM agents WHERE oid=$1", deviceID).Scan(&target.Name, &target.Platform); err != nil {
		return target, err
	}
	if target.Platform == "macOS" {
		target.Platform = "macos"
	}
	if target.Platform != "windows" && target.Platform != "linux" && target.Platform != "macos" {
		return target, ErrManualUnsupported
	}
	return target, nil
}

func (s *ManualExecutionStore) beginTarget(ctx context.Context, actor string, scope access.Scope, deviceID string) (*sql.Tx, ManualTarget, error) {
	tx, err := s.beginRecord(ctx, actor, scope)
	if err != nil {
		return nil, ManualTarget{}, err
	}
	target, err := s.target(ctx, tx, scope, deviceID)
	if err != nil {
		tx.Rollback()
		return nil, target, err
	}
	return tx, target, nil
}

func inheritedManualScope(ctx context.Context, tx *sql.Tx, destination access.Scope, profileID int64) (access.Scope, error) {
	var source access.Scope
	if _, err := tx.ExecContext(ctx, "LOCK TABLE tenant_profiles,site_profiles IN SHARE MODE"); err != nil {
		return source, err
	}
	var tenants, sites int
	if err := tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM tenant_profiles WHERE profile_id=$1),coalesce((SELECT min(tenant_id) FROM tenant_profiles WHERE profile_id=$1),0),(SELECT count(*) FROM site_profiles WHERE profile_id=$1),coalesce((SELECT min(site_id) FROM site_profiles WHERE profile_id=$1),0)", profileID).Scan(&tenants, &source.TenantID, &sites, &source.SiteID); err != nil {
		return source, err
	}
	valid := tenants == 0 && sites == 0 || tenants == 1 && source.TenantID == destination.TenantID && (sites == 0 || sites == 1 && source.SiteID == destination.SiteID)
	if !valid {
		return source, ErrNotFound
	}
	if err := lockLegacyProfileAudience(ctx, tx, source, profileID, false); err != nil {
		return source, err
	}
	return source, nil
}

type manualTaskReference struct {
	ID                     int64
	Version, Order, Tenant int
	Type                   task.Type
	Platform               task.AgentType
}

func lockManualSource(ctx context.Context, tx *sql.Tx, target ManualTarget, kind string, id int64, definition bool) (*manualLockedSource, error) {
	if (kind != "task" && kind != "profile") || id <= 0 {
		return nil, ErrManualInvalid
	}
	result := &manualLockedSource{source: ManualSource{Kind: kind, ID: id, ProfileID: id}}
	if kind == "task" {
		var parent sql.NullInt64
		err := tx.QueryRowContext(ctx, "SELECT profile_tasks FROM tasks WHERE id=$1", id).Scan(&parent)
		if errors.Is(err, sql.ErrNoRows) || err == nil && !parent.Valid {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		result.source.ProfileID = parent.Int64
	}
	sourceScope, err := inheritedManualScope(ctx, tx, target.Scope, result.source.ProfileID)
	if err != nil {
		return nil, err
	}
	result.source.Scope = sourceScope
	var profileName string
	var disabled, oversized bool
	err = tx.QueryRowContext(ctx, "SELECT CASE WHEN coalesce(octet_length(name),0)<=2048 THEN coalesce(name,'') ELSE '' END,coalesce(disabled,false),coalesce(octet_length(name),0)>2048 FROM profiles WHERE id=$1", result.source.ProfileID).Scan(&profileName, &disabled, &oversized)
	if err != nil {
		return nil, err
	}
	if disabled || oversized {
		return nil, ErrManualChanged
	}
	result.source.ProfileName = profileName
	var references []manualTaskReference
	if kind == "task" {
		var current ent.Task
		var parent sql.NullInt64
		err = tx.QueryRowContext(ctx, "SELECT id,coalesce(name,''),type,agent_type,coalesce(version,0),coalesce(disabled,false),profile_tasks FROM tasks WHERE id=$1 AND coalesce(octet_length(name),0)<=2048 FOR SHARE", id).Scan(&current.ID, &current.Name, &current.Type, &current.AgentType, &current.Version, &current.Disabled, &parent)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		if !parent.Valid || parent.Int64 != result.source.ProfileID {
			return nil, ErrManualChanged
		}
		if current.Disabled {
			return nil, ErrManualChanged
		}
		if current.AgentType.String() != target.Platform || !taskexecution.Supported(current.Type, current.AgentType) {
			return nil, ErrManualUnsupported
		}
		result.source.Name = current.Name
		result.source.Version = current.Version
		result.source.Type = current.Type.String()
		result.source.TaskCount = 1
		references = []manualTaskReference{{ID: id, Version: current.Version, Type: current.Type, Platform: current.AgentType}}
		if definition {
			var bounded bool
			err = tx.QueryRowContext(ctx, "SELECT NOT EXISTS(SELECT 1 FROM jsonb_each_text(to_jsonb(t)) v WHERE octet_length(v.value)>CASE WHEN v.key='name' THEN 2048 WHEN v.key='script' THEN 131072 ELSE 16384 END) FROM tasks t WHERE id=$1 AND profile_tasks=$2", id, result.source.ProfileID).Scan(&bounded)
			if err != nil {
				return nil, err
			}
			if !bounded {
				return nil, ErrManualUnsupported
			}
			client := ent.NewClient(ent.Driver(entsql.NewDriver(dialect.Postgres, entsql.Conn{ExecQuerier: tx})))
			current, err := client.Task.Query().Where(task.ID(int(id))).Only(ctx)
			if err != nil {
				return nil, err
			}
			current.Edges.Profile = &ent.Profile{ID: int(result.source.ProfileID), Name: profileName}
			result.task = current
		}
	} else {
		result.source.Name = profileName
		if err = lockManualProfileTasks(ctx, tx, id); err != nil {
			return nil, err
		}
		rows, err := tx.QueryContext(ctx, "SELECT id,coalesce(version,0),coalesce(\"order\",0),coalesce(tenant,0),type,agent_type FROM tasks WHERE profile_tasks=$1 AND NOT coalesce(disabled,false) AND agent_type IN ($2,'any') ORDER BY \"order\",id LIMIT 1001", id, target.Platform)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ref manualTaskReference
			if err = rows.Scan(&ref.ID, &ref.Version, &ref.Order, &ref.Tenant, &ref.Type, &ref.Platform); err != nil {
				rows.Close()
				return nil, err
			}
			references = append(references, ref)
		}
		if err = finishProfileIssueRows(rows); err != nil {
			return nil, err
		}
		if len(references) == 0 || len(references) > 1000 {
			return nil, ErrManualUnsupported
		}
		for _, ref := range references {
			if !(taskconfig.Config{TaskType: ref.Type.String(), AgentsType: ref.Platform.String()}).Supported() {
				return nil, ErrManualUnsupported
			}
			if ref.Type == task.TypeNetbirdRegister && (sourceScope.TenantID == 0 || ref.Tenant != target.Scope.TenantID) {
				return nil, ErrManualUnsupported
			}
		}
		result.source.TaskCount = len(references)
	}
	// Public version/ownership metadata, not a digest of credentials or scripts.
	fingerprint, err := json.Marshal(struct {
		Target ManualTarget
		Source ManualSource
		Tasks  []manualTaskReference
	}{target, result.source, references})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(fingerprint)
	result.source.Revision = hex.EncodeToString(sum[:])
	result.source.Name = manualPreview(result.source.Name, 512)
	result.source.ProfileName = manualPreview(result.source.ProfileName, 512)
	return result, nil
}

func manualPreview(value string, limit int) string {
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit]) + "…"
	}
	return value
}

// The held parent prevents incoming foreign keys. Bound the entire task set,
// including disabled and other-platform rows, before reading the version vector.
func lockManualProfileTasks(ctx context.Context, tx *sql.Tx, profileID int64) error {
	rows, err := tx.QueryContext(ctx, "SELECT id FROM tasks WHERE profile_tasks=$1 ORDER BY id LIMIT 1001 FOR SHARE", profileID)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		count++
	}
	if err = finishProfileIssueRows(rows); err != nil {
		return err
	}
	if count > 1000 {
		return ErrManualUnsupported
	}
	return nil
}
