package apple

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var (
	ErrUpdatePlan          = errors.New("invalid Apple update plan")
	ErrUpdatePlanIntegrity = errors.New("Apple update plan is unavailable")
	ErrUpdatePlanLimit     = errors.New("Apple update plan scope limit reached")
)

// A plan is a reviewed reusable source. Saving or archiving it changes no device
// policy; each later assignment must establish its own current eligibility.
type UpdatePlanDefinition struct {
	Name          string `json:"-" xml:"-" yaml:"-"`
	Description   string `json:"-" xml:"-" yaml:"-"`
	Platform      string `json:"-" xml:"-" yaml:"-"`
	TargetVersion string `json:"-" xml:"-" yaml:"-"`
	TargetBuild   string `json:"-" xml:"-" yaml:"-"`
	Deadline      string `json:"-" xml:"-" yaml:"-"`
	DetailsURL    string `json:"-" xml:"-" yaml:"-"`
	Archived      bool   `json:"-" xml:"-" yaml:"-"`
}

type UpdatePlan struct {
	ID         string               `json:"-" xml:"-" yaml:"-"`
	Scope      Scope                `json:"-" xml:"-" yaml:"-"`
	Revision   int                  `json:"-" xml:"-" yaml:"-"`
	Definition UpdatePlanDefinition `json:"-" xml:"-" yaml:"-"`
	Actor      string               `json:"-" xml:"-" yaml:"-"`
	CreatedAt  time.Time            `json:"-" xml:"-" yaml:"-"`
}

func (UpdatePlanDefinition) String() string     { return "[protected Apple update plan definition]" }
func (v UpdatePlanDefinition) GoString() string { return v.String() }
func (UpdatePlan) String() string               { return "[protected Apple update plan]" }
func (v UpdatePlan) GoString() string           { return v.String() }

var updatePlanBuild = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)

func (d UpdatePlanDefinition) Valid() bool {
	text := func(s string, max int) bool {
		return len(s) <= max && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
	}
	if strings.TrimSpace(d.Name) == "" || !text(d.Name, 120) || !text(d.Description, 1024) || (d.Platform != "ios" && d.Platform != "ipados" && d.Platform != "macos") || !versionPattern.MatchString(d.TargetVersion) || !updatePlanBuild.MatchString(d.TargetBuild) || !text(d.DetailsURL, 2048) {
		return false
	}
	deadline, err := time.Parse("2006-01-02T15:04:05", d.Deadline)
	if err != nil || deadline.Format("2006-01-02T15:04:05") != d.Deadline {
		return false
	}
	if d.DetailsURL != "" {
		u, err := url.Parse(d.DetailsURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
			return false
		}
	}
	return true
}
func (d UpdatePlanDefinition) Policy() UpdatePolicy {
	return UpdatePolicy{TargetVersion: d.TargetVersion, TargetBuild: d.TargetBuild, Deadline: d.Deadline, DetailsURL: d.DetailsURL}
}

type updatePlanWire struct {
	Version                                                                       int
	Name, Description, Platform, TargetVersion, TargetBuild, Deadline, DetailsURL string
	Archived                                                                      bool
}

func updatePlanPurpose(p *UpdatePlan) string {
	return fmt.Sprintf("openuem/apple/update-plan/v1/%s/%d/%d/%d/%x/%s", p.ID, p.Scope.TenantID, p.Scope.SiteID, p.Revision, sha256.Sum256([]byte(p.Actor)), p.CreatedAt.UTC().Format(time.RFC3339Nano))
}

const updatePlanColumns = `r.plan_id,r.tenant_id,r.site_id,r.revision,r.actor,r.created_at,CASE WHEN octet_length(r.encrypted_definition)<=8220 THEN r.encrypted_definition ELSE NULL END`
const updatePlanCurrentJoin = `mdm_apple_update_plans p JOIN mdm_apple_update_plan_revisions r ON r.plan_id=p.id AND r.revision=p.revision`

func (s *Store) scanUpdatePlan(row scanner) (*UpdatePlan, error) {
	p := &UpdatePlan{}
	var encrypted []byte
	if err := row.Scan(&p.ID, &p.Scope.TenantID, &p.Scope.SiteID, &p.Revision, &p.Actor, &p.CreatedAt, &encrypted); err != nil {
		return nil, notFound(err)
	}
	plain, err := s.secrets.open(encrypted, updatePlanPurpose(p))
	defer clear(plain)
	if err != nil || len(plain) > 8192 {
		return nil, ErrUpdatePlanIntegrity
	}
	var wire updatePlanWire
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(new(any)) != io.EOF || wire.Version != 1 {
		return nil, ErrUpdatePlanIntegrity
	}
	p.Definition = UpdatePlanDefinition{Name: wire.Name, Description: wire.Description, Platform: wire.Platform, TargetVersion: wire.TargetVersion, TargetBuild: wire.TargetBuild, Deadline: wire.Deadline, DetailsURL: wire.DetailsURL, Archived: wire.Archived}
	if !p.Definition.Valid() {
		return nil, ErrUpdatePlanIntegrity
	}
	return p, nil
}
func (s *Store) sealUpdatePlan(p *UpdatePlan) ([]byte, error) {
	d := p.Definition
	plain, err := json.Marshal(updatePlanWire{Version: 1, Name: d.Name, Description: d.Description, Platform: d.Platform, TargetVersion: d.TargetVersion, TargetBuild: d.TargetBuild, Deadline: d.Deadline, DetailsURL: d.DetailsURL, Archived: d.Archived})
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if len(plain) > 8192 {
		return nil, ErrUpdatePlan
	}
	return s.secrets.seal(plain, updatePlanPurpose(p))
}

func updatePlanAuthority(ctx context.Context, tx *sql.Tx, permissions *access.Store, actor string, scope Scope, capability access.Capability) error {
	if permissions == nil || scope.TenantID <= 0 || scope.SiteID <= 0 {
		return access.ErrDenied
	}
	if err := permissions.AuthorizeTransaction(ctx, tx, actor, capability, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}); err != nil {
		return err
	}
	var site int
	return notFound(tx.QueryRowContext(ctx, `SELECT s.id FROM sites s JOIN tenants t ON t.id=s.tenant_sites WHERE t.id=$1 AND s.id=$2 FOR SHARE OF s,t`, scope.TenantID, scope.SiteID).Scan(&site))
}
func auditUpdatePlan(ctx context.Context, tx *sql.Tx, scope Scope, actor, action, id string, revision int) error {
	details, err := json.Marshal(map[string]any{"site_id": scope.SiteID, "revision": revision, "result": "success"})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,details) VALUES($1,$2,$3,$4,$5)`, scope.TenantID, actor, "apple.update.plan."+action, id, details)
	return err
}

func (s *Store) SaveUpdatePlan(ctx context.Context, actor string, permissions *access.Store, scope Scope, id string, expected int, definition UpdatePlanDefinition) (*UpdatePlan, error) {
	if !definition.Valid() || expected < 0 || expected >= 2147483647 || (id == "" && expected != 0) || (id != "" && (!profileRevisionUUID(id) || expected == 0)) {
		return nil, ErrUpdatePlan
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = updatePlanAuthority(ctx, tx, permissions, actor, scope, access.ManageUpdates); err != nil {
		return nil, err
	}
	action := "revise"
	if id == "" {
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629905,hashtext($1))`, fmt.Sprintf("%d/%d", scope.TenantID, scope.SiteID)); err != nil {
			return nil, err
		}
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_update_plans WHERE tenant_id=$1 AND site_id=$2`, scope.TenantID, scope.SiteID).Scan(&count); err != nil {
			return nil, err
		}
		if count >= 1000 {
			return nil, ErrUpdatePlanLimit
		}
		id = uuid.NewString()
		action = "create"
		_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_update_plans(id,tenant_id,site_id,revision) VALUES($1,$2,$3,1)`, id, scope.TenantID, scope.SiteID)
	} else {
		var revision int
		if err = tx.QueryRowContext(ctx, `SELECT revision FROM mdm_apple_update_plans WHERE tenant_id=$1 AND site_id=$2 AND id=$3 FOR UPDATE`, scope.TenantID, scope.SiteID, id).Scan(&revision); err != nil {
			return nil, notFound(err)
		}
		if revision != expected {
			return nil, ErrConflict
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_update_plans SET revision=revision+1 WHERE id=$1`, id)
	}
	if err != nil {
		return nil, err
	}
	p := &UpdatePlan{ID: id, Scope: scope, Revision: expected + 1, Definition: definition, Actor: actor}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&p.CreatedAt); err != nil {
		return nil, err
	}
	encrypted, err := s.sealUpdatePlan(p)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_update_plan_revisions(plan_id,tenant_id,site_id,revision,actor,created_at,encrypted_definition) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, scope.TenantID, scope.SiteID, p.Revision, actor, p.CreatedAt, encrypted); err != nil {
		return nil, err
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, action, id, p.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Store) UpdatePlans(ctx context.Context, actor string, permissions *access.Store, scope Scope, after string) ([]UpdatePlan, string, error) {
	if after != "" && !profileRevisionUUID(after) {
		return nil, "", ErrUpdatePlan
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	if err = updatePlanAuthority(ctx, tx, permissions, actor, scope, access.ReadDevices); err != nil {
		return nil, "", err
	}
	var cursor any
	if after != "" {
		var found string
		if err = tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_update_plans WHERE tenant_id=$1 AND site_id=$2 AND id=$3`, scope.TenantID, scope.SiteID, after).Scan(&found); err != nil {
			return nil, "", notFound(err)
		}
		cursor = after
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+updatePlanColumns+` FROM `+updatePlanCurrentJoin+` WHERE p.tenant_id=$1 AND p.site_id=$2 AND ($3::uuid IS NULL OR p.id>$3) ORDER BY p.id LIMIT 26`, scope.TenantID, scope.SiteID, cursor)
	if err != nil {
		return nil, "", err
	}
	plans := []UpdatePlan{}
	for rows.Next() {
		p, err := s.scanUpdatePlan(rows)
		if err != nil {
			rows.Close()
			return nil, "", err
		}
		plans = append(plans, *p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(plans) > 25 {
		next = plans[24].ID
		plans = plans[:25]
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "list", "plans", 0); err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return plans, next, nil
}

// UpdatePlanHistory returns the current source and one immutable revision page.
// before is an exclusive positive revision cursor; zero starts at the newest.
func (s *Store) UpdatePlanHistory(ctx context.Context, actor string, permissions *access.Store, scope Scope, id string, before int) (*UpdatePlan, []UpdatePlan, int, error) {
	if !profileRevisionUUID(id) || before < 0 || before > 2147483647 {
		return nil, nil, 0, ErrUpdatePlan
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	defer tx.Rollback()
	if err = updatePlanAuthority(ctx, tx, permissions, actor, scope, access.ReadDevices); err != nil {
		return nil, nil, 0, err
	}
	p, err := s.scanUpdatePlan(tx.QueryRowContext(ctx, `SELECT `+updatePlanColumns+` FROM `+updatePlanCurrentJoin+` WHERE p.tenant_id=$1 AND p.site_id=$2 AND p.id=$3 FOR SHARE OF p`, scope.TenantID, scope.SiteID, id))
	if err != nil {
		return nil, nil, 0, err
	}
	if before > p.Revision {
		return nil, nil, 0, ErrUpdatePlan
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+updatePlanColumns+` FROM mdm_apple_update_plan_revisions r WHERE r.plan_id=$1 AND ($2=0 OR r.revision<$2) ORDER BY r.revision DESC LIMIT 26`, id, before)
	if err != nil {
		return nil, nil, 0, err
	}
	revisions := []UpdatePlan{}
	for rows.Next() {
		r, err := s.scanUpdatePlan(rows)
		if err != nil {
			rows.Close()
			return nil, nil, 0, err
		}
		revisions = append(revisions, *r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, 0, err
	}
	next := 0
	if len(revisions) > 25 {
		next = revisions[24].Revision
		revisions = revisions[:25]
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "read", id, p.Revision); err != nil {
		return nil, nil, 0, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, 0, err
	}
	return p, revisions, next, nil
}
