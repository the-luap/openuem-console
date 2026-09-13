package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/security/access"
)

const ProfileTagPageSize = 50

type ProfileTagQuery struct {
	Page   int
	Search string
}

func (q ProfileTagQuery) valid() bool {
	return q.Page > 0 && q.Page <= 1000000 && len(q.Search) <= 256 && utf8.ValidString(q.Search) && !strings.ContainsRune(q.Search, 0)
}

type ProfileTagChoice struct {
	ID           int64
	Name         string
	Color        string
	TenantID     int
	Organization string
}

type ProfileTagPanel struct {
	ProfileID  int64
	ApplyToAll bool
	Query      ProfileTagQuery
	Total      int
	Applied    []ProfileTagChoice
	Available  []ProfileTagChoice
	HasMore    bool
}

type ProfileEditorReview struct {
	Profile              *ent.Profile
	NamePreview          string
	NameNeedsReplacement bool
	Tasks                *LegacyTaskPage
	Tags                 *ProfileTagPanel
}

// ReadProfileEditor returns one authorized view of editable metadata, bounded
// task summaries and paged tag choices. Existing task definitions and secrets
// are never selected. The receipt commits before any result is returned.
func ReadProfileEditor(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID int64, page, size int, tagQuery ProfileTagQuery) (*ProfileEditorReview, error) {
	if page <= 0 || page > 1000000 || size <= 0 || size > 1000 || !tagQuery.valid() {
		return nil, ErrProfileInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileTransaction(ctx, db, permissions, actor, scope, profileID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result := &ProfileEditorReview{Profile: &ent.Profile{ID: int(profileID)}}
	err = tx.QueryRowContext(ctx, `SELECT CASE WHEN coalesce(octet_length(name),0)<=2048 THEN coalesce(name,'') ELSE '' END,coalesce(disabled,false),coalesce(apply_to_all,false),CASE WHEN char_length(name)>512 THEN left(name,512)||'…' ELSE coalesce(name,'') END,coalesce(octet_length(name),0)>2048 FROM profiles WHERE id=$1`, profileID).Scan(&result.Profile.Name, &result.Profile.Disabled, &result.Profile.ApplyToAll, &result.NamePreview, &result.NameNeedsReplacement)
	if err != nil {
		return nil, err
	}
	result.Tasks, err = readLegacyTaskPage(ctx, tx, profileID, page, size)
	if err != nil {
		return nil, err
	}
	result.Tags, err = readProfileTagPanel(ctx, tx, scope, profileID, tagQuery)
	if err != nil {
		return nil, err
	}
	for _, choice := range result.Tags.Applied {
		result.Profile.Edges.Tags = append(result.Profile.Edges.Tags, &ent.Tag{ID: int(choice.ID), Tag: choice.Name, Color: choice.Color})
	}
	resource := fmt.Sprintf("%d/tasks/page/%d/size/%d/tags/page/%d", profileID, result.Tasks.Page, size, result.Tags.Query.Page)
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.profiles.read',$4)`, scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func ReadProfileTagPanel(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID int64, query ProfileTagQuery) (*ProfileTagPanel, error) {
	if !query.valid() {
		return nil, ErrTagInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileTransaction(ctx, db, permissions, actor, scope, profileID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result, err := readProfileTagPanel(ctx, tx, scope, profileID, query)
	if err != nil {
		return nil, err
	}
	resource := fmt.Sprintf("%d/page/%d", profileID, result.Query.Page)
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.profile_tags.read',$4)`, scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func readProfileTagPanel(ctx context.Context, tx *sql.Tx, scope access.Scope, profileID int64, query ProfileTagQuery) (*ProfileTagPanel, error) {
	// The parent lock prevents new foreign keys. Hold existing edges and tag rows
	// to keep assignment counts, names and organization IDs stable through commit.
	locked, err := tx.QueryContext(ctx, `SELECT t.id FROM profile_tags pt JOIN tags t ON t.id=pt.tag_id WHERE pt.profile_id=$1 ORDER BY t.id FOR SHARE OF pt,t`, profileID)
	if err != nil {
		return nil, err
	}
	for locked.Next() {
	}
	err = locked.Err()
	closed := locked.Close()
	if err != nil {
		return nil, err
	}
	if closed != nil {
		return nil, closed
	}
	result := &ProfileTagPanel{ProfileID: profileID, Query: query, Applied: []ProfileTagChoice{}, Available: []ProfileTagChoice{}}
	err = tx.QueryRowContext(ctx, `SELECT coalesce(apply_to_all,false),(SELECT count(*) FROM profile_tags WHERE profile_id=$1) FROM profiles WHERE id=$1`, profileID).Scan(&result.ApplyToAll, &result.Total)
	if err != nil {
		return nil, err
	}
	result.Query.Page = min(query.Page, max(1, (result.Total+ProfileTagPageSize-1)/ProfileTagPageSize))
	const columns = `t.id,CASE WHEN char_length(t.tag)>256 THEN left(t.tag,256)||'…' ELSE coalesce(t.tag,'') END,coalesce(left(t.color,32),''),coalesce(t.tenant_tags,0),coalesce(left(org.description,128),'')`
	rows, err := tx.QueryContext(ctx, `SELECT `+columns+` FROM profile_tags pt JOIN tags t ON t.id=pt.tag_id LEFT JOIN tenants org ON org.id=t.tenant_tags WHERE pt.profile_id=$1 ORDER BY lower(t.tag),t.id OFFSET $2 LIMIT 50`, profileID, (result.Query.Page-1)*ProfileTagPageSize)
	if err != nil {
		return nil, err
	}
	result.Applied, err = scanProfileTagChoices(rows)
	if err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT `+columns+` FROM tags t JOIN tenants org ON org.id=t.tenant_tags WHERE ($1::bigint=0 OR t.tenant_tags=$1) AND NOT EXISTS(SELECT 1 FROM profile_tags pt WHERE pt.profile_id=$3 AND pt.tag_id=t.id) AND ($2='' OR CASE WHEN $2 ~ '^[1-9][0-9]*$' THEN t.id::text=$2 ELSE position(lower($2) in lower(t.tag))>0 END) ORDER BY lower(t.tag),t.id LIMIT 51 FOR SHARE OF t`, scope.TenantID, query.Search, profileID)
	if err != nil {
		return nil, err
	}
	result.Available, err = scanProfileTagChoices(rows)
	if err != nil {
		return nil, err
	}
	if len(result.Available) > ProfileTagPageSize {
		result.HasMore = true
		result.Available = result.Available[:ProfileTagPageSize]
	}
	return result, nil
}

func scanProfileTagChoices(rows *sql.Rows) ([]ProfileTagChoice, error) {
	defer rows.Close()
	result := []ProfileTagChoice{}
	for rows.Next() {
		var choice ProfileTagChoice
		if err := rows.Scan(&choice.ID, &choice.Name, &choice.Color, &choice.TenantID, &choice.Organization); err != nil {
			return nil, err
		}
		result = append(result, choice)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return result, nil
}
