package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/taskexecution"
)

type ManualChoices struct {
	Target       ManualTarget
	Kind, Search string
	Sources      []ManualSource
	More         bool
	Latest       *ManualRequest
}

// Choices searches public metadata only, with exact inherited audiences and a
// literal substring or exact numeric ID. A separate review binds confirmation.
func (s *ManualExecutionStore) Choices(parent context.Context, actor string, scope access.Scope, deviceID, kind, search string) (*ManualChoices, error) {
	if kind != "task" && kind != "profile" || len(search) > 256 || !utf8.ValidString(search) || strings.ContainsRune(search, 0) {
		return nil, ErrManualInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, target, err := s.beginTarget(ctx, actor, scope, deviceID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "LOCK TABLE tenant_profiles,site_profiles IN SHARE MODE"); err != nil {
		return nil, err
	}
	result := &ManualChoices{Target: target, Kind: kind, Search: search}
	audience := " NOT coalesce(p.disabled,false) AND coalesce(octet_length(p.name),0)<=2048 AND ((NOT EXISTS(SELECT 1 FROM tenant_profiles WHERE profile_id=p.id) AND NOT EXISTS(SELECT 1 FROM site_profiles WHERE profile_id=p.id)) OR ((SELECT count(*) FROM tenant_profiles WHERE profile_id=p.id)=1 AND EXISTS(SELECT 1 FROM tenant_profiles WHERE profile_id=p.id AND tenant_id=$1) AND (NOT EXISTS(SELECT 1 FROM site_profiles WHERE profile_id=p.id) OR ((SELECT count(*) FROM site_profiles WHERE profile_id=p.id)=1 AND EXISTS(SELECT 1 FROM site_profiles WHERE profile_id=p.id AND site_id=$2)))))"
	compatible := "t.agent_type=$3 AND t.type=ANY($4::text[])"
	applicable := "NOT coalesce(t.disabled,false) AND t.agent_type IN ($3,'any')"
	profileCompatible := "(" + compatible + ") OR (t.agent_type='any' AND (t.type IN ('netbird_install','netbird_uninstall') OR (t.type='netbird_register' AND t.tenant=$1 AND EXISTS(SELECT 1 FROM tenant_profiles WHERE profile_id=p.id AND tenant_id=$1))))"
	query := "SELECT t.id FROM tasks t JOIN profiles p ON p.id=t.profile_tasks WHERE " + audience + " AND NOT coalesce(t.disabled,false) AND " + compatible + " AND coalesce(octet_length(t.name),0)<=2048 AND ($5='' OR strpos(lower(coalesce(t.name,'')),lower($5))>0 OR t.id::text=$5) ORDER BY p.id,t.id LIMIT 51"
	if kind == "profile" {
		query = "SELECT p.id FROM profiles p WHERE " + audience + " AND EXISTS(SELECT 1 FROM tasks t WHERE t.profile_tasks=p.id AND " + applicable + ") AND NOT EXISTS(SELECT 1 FROM tasks t WHERE t.profile_tasks=p.id AND " + applicable + " AND NOT (" + profileCompatible + ")) AND (SELECT count(*) FROM (SELECT 1 FROM tasks WHERE profile_tasks=p.id LIMIT 1001) bounded)<=1000 AND ($5='' OR strpos(lower(coalesce(p.name,'')),lower($5))>0 OR p.id::text=$5) ORDER BY p.id LIMIT 51"
	}
	rows, err := tx.QueryContext(ctx, query, scope.TenantID, scope.SiteID, target.Platform, taskexecution.Types(task.AgentType(target.Platform)), search)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err = finishProfileIssueRows(rows); err != nil {
		return nil, err
	}
	for _, id := range ids {
		source, err := lockManualSource(ctx, tx, target, kind, id, false)
		// Candidate metadata may have changed before its row lock. Never return
		// a stale or newly ineligible choice; the next search can refill it.
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrManualChanged) || errors.Is(err, ErrManualUnsupported) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if search != "" {
			table := "tasks"
			if kind == "profile" {
				table = "profiles"
			}
			var matches bool
			err = tx.QueryRowContext(ctx, "SELECT strpos(lower(coalesce(name,'')),lower($2))>0 OR id::text=$2 FROM "+table+" WHERE id=$1", id, search).Scan(&matches)
			if err != nil {
				return nil, err
			}
			if !matches {
				continue
			}
		}
		if len(result.Sources) == 50 {
			result.More = true
			break
		}
		// The review fingerprint belongs only on the separately audited review.
		source.source.Revision = ""
		result.Sources = append(result.Sources, source.source)
	}
	// Status is a read snapshot; locking a request here would invert the
	// dispatcher's request-then-target lock order. The receipt rechecks it.
	result.Latest, err = scanManual(tx.QueryRowContext(ctx, "SELECT "+manualColumns+" FROM uem_manual_execution r WHERE r.device_id=$1 AND r.tenant_id=$2 AND r.site_id=$3 ORDER BY r.requested_at DESC,r.id DESC LIMIT 1", deviceID, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		result.Latest = nil
	} else if err != nil {
		return nil, err
	}
	resource := fmt.Sprintf("%s/%s", deviceID, kind)
	if _, err = tx.ExecContext(ctx, "INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.execution.choices',$4)", scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
