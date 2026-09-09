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
