package inventory

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var (
	ErrTagInvalid  = errors.New("invalid organization tag")
	ErrTagConflict = errors.New("organization tag changed")
	ErrTagName     = errors.New("tag name is unavailable")
	ErrTagUsed     = errors.New("tag still has assignments")
)

type TagDefinition struct{ Name, Description, Color string }
type OrganizationTag struct {
	ID       int64
	Revision string
	TagDefinition
	Used bool
}
type TagPage struct {
	Tags []OrganizationTag
	Next int64
}

func (d TagDefinition) Valid() bool {
	text := func(s string, max int) bool {
		return len(s) <= max && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
	}
	if strings.TrimSpace(d.Name) == "" || !text(d.Name, 255) || !text(d.Description, 2048) || len(d.Color) != 7 || d.Color[0] != '#' {
		return false
	}
	for _, c := range d.Color[1:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// Tags belong to a whole organization; a site grant cannot authorize catalog
// metadata or a definition that affects assignments elsewhere in that organization.
func beginTagTransaction(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, capability access.Capability) (*sql.Tx, error) {
	if scope.SiteID != 0 {
		return nil, access.ErrDenied
	}
	return beginGroupTransaction(ctx, db, permissions, actor, scope, capability)
}

// Legacy text is bounded before transfer. An unsupported row fails closed; it
// must not silently truncate a value and allow an edit to erase unseen content.
const tagColumns = `id,uem_revision::text,CASE WHEN octet_length(tag)<=255 THEN tag END,CASE WHEN octet_length(coalesce(description,''))<=2048 THEN coalesce(description,'') END,CASE WHEN octet_length(color)<=7 THEN color END`
const tagUsed = `EXISTS(SELECT 1 FROM agent_tags WHERE tag_id=$1) OR EXISTS(SELECT 1 FROM profile_tags WHERE tag_id=$1) OR EXISTS(SELECT 1 FROM tags WHERE tag_children=$1 OR (id=$1 AND (tag_children IS NOT NULL OR task_tags IS NOT NULL)))`

func scanTag(row groupScanner) (*OrganizationTag, error) {
	var tag OrganizationTag
	err := row.Scan(&tag.ID, &tag.Revision, &tag.Name, &tag.Description, &tag.Color)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &tag, nil
}
func tagEvent(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope, action, resource string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,0,$2,$3,$4)`, scope.TenantID, actor, "inventory.tags."+action, resource)
	return err
}

func ListOrganizationTags(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, filter ReportFilter) (*TagPage, error) {
	if !filter.Valid() {
		return nil, ErrTagInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginTagTransaction(ctx, db, permissions, actor, scope, access.ReadDevices)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT `+tagColumns+` FROM tags WHERE tenant_tags=$1 AND id>$2 AND ($3='' OR strpos(lower(tag),lower($3))>0 OR strpos(lower(coalesce(description,'')),lower($3))>0) ORDER BY id LIMIT 26`, scope.TenantID, filter.After, filter.Search)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &TagPage{}
	for rows.Next() {
		tag, err := scanTag(rows)
		if err != nil {
			return nil, err
		}
		page.Tags = append(page.Tags, *tag)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	if len(page.Tags) > 25 {
		page.Tags = page.Tags[:25]
		page.Next = page.Tags[24].ID
	}
	if err = tagEvent(ctx, tx, actor, scope, "list", "organization-tags"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}

func ReadOrganizationTag(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, id int64) (*OrganizationTag, error) {
	if id <= 0 {
		return nil, ErrTagInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginTagTransaction(ctx, db, permissions, actor, scope, access.ReadDevices)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	tag, err := scanTag(tx.QueryRowContext(ctx, `SELECT `+tagColumns+` FROM tags WHERE tenant_tags=$1 AND id=$2 FOR SHARE`, scope.TenantID, id))
	if err != nil {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT `+tagUsed, id).Scan(&tag.Used); err != nil {
		return nil, err
	}
	if err = tagEvent(ctx, tx, actor, scope, "read", strconv.FormatInt(id, 10)+"/"+tag.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return tag, nil
}

func SaveOrganizationTag(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, id int64, revision string, definition TagDefinition) (*OrganizationTag, error) {
	if id < 0 || !definition.Valid() || id == 0 && revision != "" || id > 0 && !canonicalRequestID(revision) {
		return nil, ErrTagInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginTagTransaction(ctx, db, permissions, actor, scope, access.ManageTags)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	action := "create"
	if id > 0 {
		current, err := scanTag(tx.QueryRowContext(ctx, `SELECT `+tagColumns+` FROM tags WHERE tenant_tags=$1 AND id=$2 FOR UPDATE`, scope.TenantID, id))
		if err != nil {
			return nil, err
		}
		if current.Revision != revision {
			return nil, ErrTagConflict
		}
		action = "update"
	}
	var tag *OrganizationTag
	if id == 0 {
		tag, err = scanTag(tx.QueryRowContext(ctx, `INSERT INTO tags(tag,description,color,tenant_tags) VALUES($1,$2,$3,$4) RETURNING `+tagColumns, definition.Name, definition.Description, definition.Color, scope.TenantID))
	} else {
		tag, err = scanTag(tx.QueryRowContext(ctx, `UPDATE tags SET tag=$1,description=$2,color=$3 WHERE tenant_tags=$4 AND id=$5 RETURNING `+tagColumns, definition.Name, definition.Description, definition.Color, scope.TenantID, id))
	}
	if err != nil {
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "23505" {
			return nil, ErrTagName
		}
		return nil, err
	}
	if err = tagEvent(ctx, tx, actor, scope, action, strconv.FormatInt(tag.ID, 10)+"/"+revision+"/"+tag.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return tag, nil
}

// Delete only unused tags. FOR UPDATE conflicts with new foreign-key references
// until commit, so a concurrent assignment cannot be silently removed by cascade.
func DeleteOrganizationTag(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, id int64, revision string) error {
	if id <= 0 || !canonicalRequestID(revision) {
		return ErrTagInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginTagTransaction(ctx, db, permissions, actor, scope, access.ManageTags)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tag, err := scanTag(tx.QueryRowContext(ctx, `SELECT `+tagColumns+` FROM tags WHERE tenant_tags=$1 AND id=$2 FOR UPDATE`, scope.TenantID, id))
	if err != nil {
		return err
	}
	if tag.Revision != revision {
		return ErrTagConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT `+tagUsed, id).Scan(&tag.Used); err != nil {
		return err
	}
	if tag.Used {
		return ErrTagUsed
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM tags WHERE id=$1 AND tenant_tags=$2`, id, scope.TenantID); err != nil {
		return err
	}
	if err = tagEvent(ctx, tx, actor, scope, "delete", strconv.FormatInt(id, 10)+"/"+revision); err != nil {
		return err
	}
	return tx.Commit()
}
