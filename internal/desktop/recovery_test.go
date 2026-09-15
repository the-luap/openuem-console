package desktop

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/testsupport/recoverydb"
	"github.com/open-uem/openuem-console/internal/testsupport/recoveryfixture"
)

func TestDesktopRecoveryPreservesIndividualIdentityAndRevocation(t *testing.T) {
	db, source := recoverydb.New(t)
	if _, err := db.Exec(`CREATE TABLE tenants(id BIGINT PRIMARY KEY); CREATE TABLE sites(id BIGINT PRIMARY KEY,tenant_sites BIGINT NOT NULL REFERENCES tenants(id),description TEXT NOT NULL DEFAULT 'Isolated recovery site'); INSERT INTO tenants VALUES(1); INSERT INTO sites(id,tenant_sites) VALUES(1,1)`); err != nil {
		t.Fatal(err)
	}
	master := "isolated-desktop-recovery-master-key"
	s, err := NewStore(db, master)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Registry.EnsureAuthority(t.Context(), 1, "Recovery organization", "https://uem.example.test", "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	scope := registry.Scope{TenantID: 1, SiteID: 1}
	invitation, err := s.Registry.Invite(t.Context(), registry.InvitationOptions{Scope: scope, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	token := invitation.URL[strings.LastIndex(invitation.URL, "/")+1:]
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	request, err := keys.Request(token, "windows", "amd64", "Recovery endpoint")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := s.Registry.Claim(t.Context(), *request)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(issued.Certificate))
	if block == nil {
		t.Fatal("missing issued certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	target, environment := recoveryfixture.Cycle(t, source, map[string]string{"ENCRYPTION_MASTER_KEY": master})
	restored, err := NewStore(target, environment["ENCRYPTION_MASTER_KEY"])
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	replayed, err := restored.Registry.Claim(t.Context(), *request)
	if err != nil || !reflect.DeepEqual(replayed, issued) {
		t.Fatal("restored individual issuance lost its exact retry", err)
	}
	access, err := registry.NewAccessStore(target)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := access.AuthenticateCertificate(t.Context(), issued.DeviceID, certificate)
	if err != nil || identity.ID != issued.DeviceID {
		t.Fatal("original desktop certificate rejected after restore", err)
	}
	if _, err := restored.Registry.EnsureAuthority(t.Context(), 1, "Recovery organization", "https://uem.example.test", "admin", nil, nil); err != nil {
		t.Fatal("restored organization authority could not be reopened", err)
	}
	if err := restored.Registry.RevokeIdentity(t.Context(), scope, issued.DeviceID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := access.AuthenticateCertificate(t.Context(), issued.DeviceID, certificate); !errors.Is(err, registry.ErrDenied) {
		t.Fatal("restored registry could not revoke original identity", err)
	}
}
