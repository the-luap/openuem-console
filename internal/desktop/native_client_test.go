package desktop

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/gateway"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

func TestNativeEnrollmentClientClaimsAndRecoversThroughThePinnedGateway(t *testing.T) {
	f := newCatalogFixture(t)
	ctx := context.Background()
	publicServer := httptest.NewUnstartedServer(nil)
	defer publicServer.Close()
	origin := "https://" + publicServer.Listener.Addr().String()
	if _, err := f.store.db.Exec(`INSERT INTO tenants VALUES(3); INSERT INTO sites VALUES(4,3)`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Registry.EnsureAuthority(ctx, 3, "Native client integration", origin, "fixture-admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	data, release, _ := f.prepare(t, f.manifest)
	if _, err := f.catalog.Accept(ctx, data, "fixture-release-admin"); err != nil {
		t.Fatal(err)
	}
	invitation, err := f.store.InviteInstaller(ctx, f.catalog, registry.InvitationOptions{Scope: registry.Scope{TenantID: 3, SiteID: 4}, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(30 * time.Minute)}, release.Digest(), origin, "fixture-admin")
	if err != nil {
		t.Fatal(err)
	}
	identity, bundle := publicTestIdentity(t, "native-client-test-gateway")
	policy, err := clientidentity.FromPEM(bundle)
	if err != nil {
		t.Fatal(err)
	}
	public, err := NewPublicHandler(f.store, f.catalog, origin, policy)
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewUnstartedServer(public)
	backend.Config = public.Server("")
	backend.Config.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
	backend.TLS = backend.Config.TLSConfig.Clone()
	backend.EnableHTTP2 = true
	backend.StartTLS()
	defer func() { backend.CloseClientConnections(); public.Close(); backend.Close() }()
	backendRoots := x509.NewCertPool()
	backendRoots.AddCert(backend.Certificate())
	g, err := gateway.New(gateway.Config{PublicOrigin: origin, AppleURL: backend.URL, ConsoleURL: backend.URL, AuthURL: backend.URL, DesktopURL: backend.URL, AdminNetworks: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}, BackendTLS: &tls.Config{Certificates: []tls.Certificate{identity}, RootCAs: backendRoots}})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	publicServer.Config.Handler = g
	publicServer.EnableHTTP2 = true
	publicServer.StartTLS()
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(publicServer.Certificate())
	client, err := enrollment.NewHTTPClient(origin, serverRoots)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Broker.Wipe()
	token := invitation.URL[strings.LastIndex(invitation.URL, "/")+1:]
	request, err := keys.Request(token, "windows", "amd64", "Native HTTPS client fixture")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := client.Claim(ctx, *request)
	if err != nil {
		t.Fatal("native client did not accept the gateway/registry response", err)
	}
	if issued.TenantID != 3 || issued.SiteID != 4 || issued.Endpoint != "wss"+strings.TrimPrefix(origin, "https")+"/agent-channel" {
		t.Fatal("native client received incorrect placement or endpoint")
	}
	// Reconstruct the native client and regenerate the CSR with the same locally
	// retained keys, as after an interrupted installer response or process restart.
	client.CloseIdleConnections()
	restarted, err := enrollment.NewHTTPClient(origin, serverRoots)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.CloseIdleConnections()
	retry, err := keys.Request(token, "windows", "amd64", "Native HTTPS client fixture")
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.Claim(ctx, *retry)
	if err != nil || *recovered != *issued {
		t.Fatal("native client retry did not recover the same identity", err)
	}
	var uses, count int
	if err = f.store.db.QueryRow(`SELECT (SELECT uses FROM uem_agent_invitations WHERE id=$1),(SELECT count(*) FROM uem_agent_identities WHERE invitation_id=$1)`, invitation.ID).Scan(&uses, &count); err != nil || uses != 1 || count != 1 {
		t.Fatal("native retry consumed another use or identity", err)
	}
	if err = f.catalog.Withdraw(ctx, release.Digest(), "fixture-release-admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Claim(ctx, *retry); err != enrollment.ErrEnrollmentUnavailable {
		t.Fatal("native client did not reject a withdrawn installer invitation", err)
	}
}
