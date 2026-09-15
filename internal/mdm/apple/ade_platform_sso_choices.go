package apple

import (
	"context"
	"fmt"
	"strings"
)

type ADEPlatformSSOChoice struct {
	ID        string `json:"id"`
	ProfileID string `json:"profile"`
	Label     string `json:"label"`
	Eligible  bool   `json:"eligible"`
}

// Choices expose current catalog revision metadata only. Selecting a choice pins
// its snapshot even if the catalog changes before the policy is submitted.
func (s *Store) ADEPlatformSSOChoices(ctx context.Context, tenant int, query, after string) ([]ADEPlatformSSOChoice, string, error) {
	query = strings.TrimSpace(query)
	if tenant <= 0 || len(query) > 128 || query != "" && !validMacAppText(query, 128) || after != "" && !profileRevisionUUID(after) {
		return nil, "", ErrADEPlatformSSO
	}
	var cursor any
	if after != "" {
		var found string
		if err := s.db.QueryRowContext(ctx, `SELECT id FROM mdm_apple_profiles WHERE tenant_id=$1 AND id=$2 AND payload_scope='System' AND payload_types @> '["com.apple.extensiblesso"]'::jsonb`, tenant, after).Scan(&found); err != nil {
			return nil, "", notFound(err)
		}
		cursor = after
	}
	pattern := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(query) + "%"
	rows, err := s.db.QueryContext(ctx, `SELECT revision_id,id,name,revision FROM mdm_apple_profiles WHERE tenant_id=$1 AND payload_scope='System' AND payload_types @> '["com.apple.extensiblesso"]'::jsonb AND ($2::uuid IS NULL OR id>$2) AND (name ILIKE $3 OR identifier ILIKE $3) ORDER BY id LIMIT 26`, tenant, cursor, pattern)
	if err != nil {
		return nil, "", err
	}
	items := []ADEPlatformSSOChoice{}
	for rows.Next() {
		var item ADEPlatformSSOChoice
		var name string
		var revision int
		if err = rows.Scan(&item.ID, &item.ProfileID, &name, &revision); err != nil {
			rows.Close()
			return nil, "", err
		}
		item.Label = fmt.Sprintf("%s · Revision %d", name, revision)
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > 25 {
		items = items[:25]
		next = items[24].ProfileID
	}
	for i := range items {
		p, err := s.ProfileRevisionPayload(ctx, tenant, items[i].ID)
		if err != nil {
			return nil, "", err
		}
		items[i].Eligible = validateADEPlatformSSOProfile(p) == nil
		clear(p.Payload)
	}
	return items, next, nil
}

// Corrections can select any retained revision of the enrollment's profile.
func (s *Store) ADEPlatformSSORevisionChoices(ctx context.Context, scope Scope, device, query, after string) ([]ADEPlatformSSOChoice, string, error) {
	query = strings.TrimSpace(query)
	if len(query) > 128 || query != "" && !validMacAppText(query, 128) || after != "" && !profileRevisionUUID(after) {
		return nil, "", ErrADEPlatformSSO
	}
	r, err := s.ADEPlatformSSOStatus(ctx, scope, device)
	if err != nil {
		return nil, "", err
	}
	if r == nil {
		return nil, "", ErrNotFound
	}
	var cursor any
	if after != "" {
		var revision int
		if err = s.db.QueryRowContext(ctx, `SELECT revision FROM mdm_apple_profile_revisions WHERE tenant_id=$1 AND profile_id=$2 AND id=$3`, scope.TenantID, r.ProfileID, after).Scan(&revision); err != nil {
			return nil, "", notFound(err)
		}
		cursor = revision
	}
	pattern := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(query) + "%"
	rows, err := s.db.QueryContext(ctx, `SELECT id,profile_id,name,revision FROM mdm_apple_profile_revisions WHERE tenant_id=$1 AND profile_id=$2 AND ($3::int IS NULL OR revision<$3) AND (name ILIKE $4 OR identifier ILIKE $4) ORDER BY revision DESC LIMIT 26`, scope.TenantID, r.ProfileID, cursor, pattern)
	if err != nil {
		return nil, "", err
	}
	items := []ADEPlatformSSOChoice{}
	for rows.Next() {
		var item ADEPlatformSSOChoice
		var name string
		var revision int
		if err = rows.Scan(&item.ID, &item.ProfileID, &name, &revision); err != nil {
			rows.Close()
			return nil, "", err
		}
		item.Label = fmt.Sprintf("%s · Revision %d", name, revision)
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > 25 {
		items = items[:25]
		next = items[24].ID
	}
	for i := range items {
		p, err := s.ProfileRevisionPayload(ctx, scope.TenantID, items[i].ID)
		if err != nil {
			return nil, "", err
		}
		items[i].Eligible = validateADEPlatformSSOProfile(p) == nil
		clear(p.Payload)
	}
	return items, next, nil
}
