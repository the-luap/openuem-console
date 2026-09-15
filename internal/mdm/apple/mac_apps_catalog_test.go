package apple

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestSoftwareCatalogApprovalEncryptionWithdrawalAndScope(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	if _, err := s.db.Exec(`CREATE TABLE users(uid TEXT PRIMARY KEY);INSERT INTO users VALUES('admin'),('operator')`); err != nil {
		t.Fatal(err)
	}
	permissions, err := access.NewStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	if err = permissions.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = permissions.Bootstrap(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = permissions.ReplaceGrants(ctx, "admin", "operator", 0, []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}); err != nil {
		t.Fatal(err)
	}
	input := testMacAppPackage()
	scope := Scope{TenantID: 1}
	for _, actor := range []string{"operator", "unknown"} {
		if _, err = s.PublishMacAppPackage(ctx, scope, input, actor, permissions); !errors.Is(err, access.ErrDenied) {
			t.Fatal("unapproved publisher accepted", actor, err)
		}
	}
	if _, err = s.PublishMacAppPackage(ctx, scope, input, "admin", nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("missing authorization accepted", err)
	}
	v, err := s.PublishMacAppPackage(ctx, scope, input, "admin", permissions)
	if err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err = s.db.QueryRow(`SELECT encrypted_url FROM uem_software_versions WHERE id=$1`, v.ID).Scan(&sealed); err != nil || bytes.Contains(sealed, []byte("not-for-pages")) {
		t.Fatal("source URL stored in plaintext", err)
	}
	if _, err = s.secrets.open(sealed, secretPurpose(2, v.ID, "software_url")); err == nil {
		t.Fatal("source decrypted in another tenant")
	}
	if _, err = s.secrets.open(sealed, secretPurpose(1, uuid.NewString(), "software_url")); err == nil {
		t.Fatal("source decrypted for another artifact")
	}
	items, next, err := s.SoftwareVersions(ctx, Scope{TenantID: 1, SiteID: 1}, "")
	if err != nil || next != "" || len(items) != 1 || items[0].ID != v.ID {
		t.Fatal("approved package missing", err)
	}
	public, err := json.Marshal(items)
	if err != nil || bytes.Contains(public, []byte("not-for-pages")) || bytes.Contains(public, []byte("packages.example.test")) {
		t.Fatal("catalog disclosed download capability")
	}
	if _, _, err = s.SoftwareVersions(ctx, Scope{TenantID: 2}, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant cursor accepted", err)
	}
	for _, query := range []string{
		`UPDATE uem_software_versions SET version='43' WHERE id=$1`,
		`UPDATE uem_software_versions SET artifact_sha256=repeat('b',64) WHERE id=$1`,
		`UPDATE uem_software_versions SET encrypted_url=encrypted_url||'x'::bytea WHERE id=$1`,
	} {
		if _, err = s.db.Exec(query, v.ID); err == nil {
			t.Fatal("approved artifact changed")
		}
	}
	if err = s.WithdrawSoftwareVersion(ctx, Scope{TenantID: 2}, v.ID, "admin", permissions); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant withdrawal accepted", err)
	}
	if err = s.WithdrawSoftwareVersion(ctx, scope, v.ID, "operator", permissions); !errors.Is(err, access.ErrDenied) {
		t.Fatal("operator withdrew approved artifact", err)
	}
	if err = s.WithdrawSoftwareVersion(ctx, scope, v.ID, "admin", permissions); err != nil {
		t.Fatal(err)
	}
	if err = s.WithdrawSoftwareVersion(ctx, scope, v.ID, "admin", permissions); err != nil {
		t.Fatal("withdrawal was not idempotent", err)
	}
	if _, err = s.db.Exec(`UPDATE uem_software_versions SET withdrawn_at=NULL WHERE id=$1`, v.ID); err == nil {
		t.Fatal("withdrawn artifact was reapproved in place")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, _, err = s.macAppArtifactTx(ctx, tx, 1, v.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("withdrawn artifact can still be issued", err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE action IN ('apple.software.version.publish','apple.software.version.withdraw')`).Scan(&count); err != nil || count != 2 {
		t.Fatal("approval or withdrawal audit missing or duplicated", count, err)
	}
}

func TestSoftwareCatalogStablePagesAndAuditRollback(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	input := testMacAppPackage()
	for i := range 102 {
		input.Version = fmt.Sprint(i)
		if _, err := s.publishMacAppPackage(ctx, Scope{TenantID: 1}, input, "admin", nil); err != nil {
			t.Fatal(err)
		}
	}
	first, cursor, err := s.SoftwareVersions(ctx, Scope{TenantID: 1}, "")
	if err != nil || len(first) != 100 || cursor == "" {
		t.Fatal("catalog is not bounded", len(first), err)
	}
	last, next, err := s.SoftwareVersions(ctx, Scope{TenantID: 1}, cursor)
	if err != nil || len(last) != 2 || next != "" || first[0].Version != "101" || last[1].Version != "0" {
		t.Fatal("catalog cursor skipped or duplicated versions", len(last), err)
	}
	selected, after, err := s.SearchApprovedMacApplications(ctx, Scope{TenantID: 1}, "", "Editor", first[0].PackageID)
	if err != nil || len(selected) != 100 || after != cursor {
		t.Fatal("approved picker pagination differs from catalog", err)
	}
	selected, after, err = s.SearchApprovedMacApplications(ctx, Scope{TenantID: 1}, after, "com.example.Editor", first[0].PackageID)
	if err != nil || len(selected) != 2 || after != "" {
		t.Fatal("approved picker omitted older versions", err)
	}
	for _, query := range []string{"%", "_", `\`, "no such app"} {
		if selected, _, err = s.SearchApprovedMacApplications(ctx, Scope{TenantID: 1}, "", query, ""); err != nil || len(selected) != 0 {
			t.Fatal("application search interpreted wildcards", query, err)
		}
	}
	if selected, _, err = s.SearchApprovedMacApplications(ctx, Scope{TenantID: 1}, "", "", uuid.NewString()); err != nil || len(selected) != 0 {
		t.Fatal("package filter returned unrelated versions", err)
	}
	if _, _, err = s.SearchApprovedMacApplications(ctx, Scope{TenantID: 2}, cursor, "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("picker cursor crossed tenant", err)
	}
	if _, err = s.db.Exec(`UPDATE uem_software_versions SET withdrawn_at=clock_timestamp() WHERE id=$1`, first[0].ID); err != nil {
		t.Fatal(err)
	}
	selected, _, err = s.SearchApprovedMacApplications(ctx, Scope{TenantID: 1}, "", "", "")
	if err != nil || len(selected) != 100 || selected[0].ID == first[0].ID {
		t.Fatal("withdrawn revision remained selectable", err)
	}
	if _, err = s.db.Exec(`CREATE FUNCTION reject_software_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$;CREATE TRIGGER reject_software_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_software_audit()`); err != nil {
		t.Fatal(err)
	}
	input.Identifier = "com.example.NewPackage"
	if _, err = s.publishMacAppPackage(ctx, Scope{TenantID: 1}, input, "admin", nil); err == nil || strings.Contains(err.Error(), "not-for-pages") {
		t.Fatal("audit failure allowed approval or exposed source", err)
	}
	var exists bool
	if err = s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM uem_software_packages WHERE identifier=$1)`, input.Identifier).Scan(&exists); err != nil || exists {
		t.Fatal("failed approval left a catalog identity behind", err)
	}
}
