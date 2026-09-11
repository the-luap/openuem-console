//go:build linux

package reference

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/ent"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/ent/wingetconfigexclusion"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/nats/enrollment/servicecredentials"
	"github.com/open-uem/openuem-console/internal/desktop/protocol"
)

const referencePackage = "Non-executable reference installer integrity fixture.\n"
const referenceAgent = "Non-executable reference agent binding fixture.\n"

func fixture(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENUEM_REFERENCE_FIXTURE") != "1" {
		t.Skip("requires the isolated reference composition runner")
	}
	if os.Geteuid() == 0 {
		t.Fatal("reference fixture must run without root")
	}
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := keyfile.Create(path, data); err != nil {
		t.Fatal("cannot create a protected reference fixture input")
	}
}

// Public HTTPS certificates and release signing keys remain synthetic acceptance
// inputs. Administrator trust comes from the actual private PKI initializer.
func TestReferencePrepare(t *testing.T) {
	fixture(t)
	makeCA := func(name string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		parsed, _ := x509.ParseCertificate(der)
		return parsed, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	ca, caKey, caPEM := makeCA("Reference public TLS fixture")
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"uem.example.test"},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	write(t, "/state/public/server.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write(t, "/state/public/server.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	write(t, "/state/public-ca.pem", caPEM)
	if os.Getenv("OPENUEM_REFERENCE_TLS_RENEWAL") == "1" {
		nextKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal("cannot prepare the next synthetic public TLS key")
		}
		leaf.SerialNumber = big.NewInt(3)
		nextDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &nextKey.PublicKey, caKey)
		if err != nil {
			t.Fatal("cannot prepare the next synthetic public TLS certificate")
		}
		nextPrivate, _ := x509.MarshalPKCS8PrivateKey(nextKey)
		write(t, "/state/ready/renewed.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nextDER}))
		write(t, "/state/ready/renewed.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: nextPrivate}))
	}
	release, signing, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(signing)
	encoded, _ := x509.MarshalPKIXPublicKey(release)
	write(t, "/state/release-keys.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}))
	digest := sha256.Sum256([]byte(referencePackage))
	agentDigest := sha256.Sum256([]byte(referenceAgent))
	now := time.Now().UTC()
	manifest := artifacts.Manifest{Schema: artifacts.Schema, Sequence: 1, Version: "0.12.0", PublishedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Artifacts: []artifacts.Artifact{{Platform: "windows", Architecture: "amd64", Format: "msi", Filename: "openuem-agent-0.12.0-windows-amd64.msi",
			Size: int64(len(referencePackage)), SHA256: hex.EncodeToString(digest[:]), AgentSize: int64(len(referenceAgent)), AgentSHA256: hex.EncodeToString(agentDigest[:])}}}
	envelope, err := artifacts.Sign(manifest, signing, now)
	if err != nil {
		t.Fatal("cannot sign synthetic release metadata")
	}
	verified, err := artifacts.Verify(envelope, []ed25519.PublicKey{release}, now, artifacts.Checkpoint{})
	if err != nil {
		t.Fatal("synthetic release signature did not verify")
	}
	directory := filepath.Join("/state/releases", verified.Digest())
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal("cannot stage synthetic package directory")
	}
	write(t, filepath.Join(directory, manifest.Artifacts[0].Filename), []byte(referencePackage))
	write(t, "/state/release-candidate.json", envelope)
}

func TestReferenceReleaseDownload(t *testing.T) {
	fixture(t)
	data, err := os.ReadFile("/run/release-candidate.json")
	if err != nil {
		t.Fatal("synthetic release candidate is unavailable")
	}
	public, err := os.ReadFile("/run/release-keys.pem")
	if err != nil {
		t.Fatal("synthetic release trust is unavailable")
	}
	block, _ := pem.Decode(public)
	if block == nil {
		t.Fatal("synthetic release trust is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		t.Fatal("synthetic release public key is invalid")
	}
	release, err := artifacts.Verify(data, []ed25519.PublicKey{key}, time.Now(), artifacts.Checkpoint{})
	if err != nil {
		t.Fatal("synthetic release signature is invalid")
	}
	target, err := release.Select("windows", "amd64")
	if err != nil {
		t.Fatal("synthetic release target is missing")
	}
	path := protocol.DownloadPath(release.Digest(), target.Platform, target.Architecture)
	client := client(t)
	if os.Getenv("OPENUEM_REFERENCE_ACTION") == "withdrawn" {
		status, body, _ := request(t, client, path, nil)
		if status != http.StatusNotFound || strings.Contains(body, referencePackage) {
			t.Fatal("withdrawn package remained available through the gateway")
		}
		return
	}
	for _, method := range []string{http.MethodHead, http.MethodGet, "range"} {
		verb := method
		if verb == "range" {
			verb = http.MethodGet
		}
		request, err := http.NewRequestWithContext(t.Context(), verb, "https://uem.example.test:8443"+path, nil)
		if err != nil {
			t.Fatal("cannot create synthetic package request")
		}
		if method == "range" {
			request.Header.Set("Range", "bytes=4-11")
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("gateway package request failed")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		response.Body.Close()
		status, size := http.StatusOK, target.Size
		if method == "range" {
			status, size = http.StatusPartialContent, 8
		}
		if err != nil || response.StatusCode != status || response.ContentLength != size || !strings.Contains(response.Header.Get("Content-Disposition"), target.Filename) || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("gateway package response lost verified size, status or download headers")
		}
		if method == http.MethodHead && len(body) != 0 || method == "range" && string(body) != referencePackage[4:12] {
			t.Fatal("gateway changed package HEAD or range behavior")
		}
		if method == http.MethodGet {
			digest := sha256.Sum256(body)
			if hex.EncodeToString(digest[:]) != target.SHA256 || string(body) != referencePackage {
				t.Fatal("gateway download differs from the signed approved package")
			}
		}
	}
}

func TestReferenceIdle(t *testing.T) {
	fixture(t)
	ctx, stop := signal.NotifyContext(t.Context(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	<-ctx.Done()
}

func roots(t *testing.T) *x509.CertPool {
	t.Helper()
	data, err := os.ReadFile("/trust.pem")
	pool := x509.NewCertPool()
	if err != nil || !pool.AppendCertsFromPEM(data) {
		t.Fatal("reference client trust is unavailable")
	}
	return pool
}

func client(t *testing.T) *http.Client {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots(t)}, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	jar, _ := cookiejar.New(nil)
	return &http.Client{Transport: transport, Jar: jar, Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestReferenceGatewayTLS(t *testing.T) {
	fixture(t)
	expected := os.Getenv("OPENUEM_REFERENCE_TLS_SHA256")
	if value, err := hex.DecodeString(expected); err != nil || len(value) != sha256.Size {
		t.Fatal("expected public TLS fingerprint is unavailable")
	}
	client := client(t)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("https://uem.example.test:8443/enroll/unknown")
		if err == nil {
			_ = response.Body.Close()
			if response.TLS != nil && len(response.TLS.PeerCertificates) != 0 {
				digest := sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
				if hex.EncodeToString(digest[:]) == expected {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("gateway did not present the selected public TLS generation")
}

func TestReferencePublishedTLSFiles(t *testing.T) {
	fixture(t)
	directory := "/publication"
	if selected := os.Getenv("OPENUEM_REFERENCE_TLS_GENERATION"); selected != "" {
		target, err := os.Readlink("/publication/current")
		if err != nil || target != selected {
			t.Fatal("Linux publication link does not match the selected generation")
		}
		directory += "/current"
	}
	for _, path := range []string{directory + "/fullchain.pem", directory + "/private.pem"} {
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			t.Fatal("published TLS fixture input is not readable", path)
		}
	}
	if _, err := tls.LoadX509KeyPair(directory+"/fullchain.pem", directory+"/private.pem"); err != nil {
		t.Fatal("published TLS fixture certificate and private key do not match")
	}
}

func TestReferenceSelectPublicTLS(t *testing.T) {
	fixture(t)
	selected := os.Getenv("OPENUEM_REFERENCE_TLS_GENERATION")
	if !regexp.MustCompile(`^generation-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(selected) {
		t.Fatal("next fixture publication generation is invalid")
	}
	publication, err := os.OpenRoot("/publication")
	if err != nil {
		t.Fatal("fixture publication is unavailable")
	}
	defer publication.Close()
	if err := publication.Symlink(selected, "next"); err != nil {
		t.Fatal("fixture publication selection could not be staged")
	}
	if err := publication.Rename("next", "current"); err != nil {
		t.Fatal("fixture publication selection could not be committed")
	}
	directory, err := publication.Open(".")
	if err != nil {
		t.Fatal("fixture publication directory is unavailable")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		t.Fatal("fixture publication selection could not be synced")
	}
}

func request(t *testing.T, client *http.Client, path string, form url.Values) (int, string, string) {
	t.Helper()
	method := http.MethodGet
	var body io.Reader
	if form != nil {
		method, body = http.MethodPost, strings.NewReader(form.Encode())
	}
	origin := "https://uem.example.test:8443"
	req, _ := http.NewRequestWithContext(t.Context(), method, origin+path, body)
	req.Header.Set("Accept-Language", "en")
	if claimed := os.Getenv("OPENUEM_REFERENCE_FORGED_SOURCE"); claimed != "" {
		req.Header.Set("X-Forwarded-For", claimed)
		req.Header.Set("X-Real-IP", claimed)
		req.Header.Set("Forwarded", "for="+claimed)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		for _, cookie := range client.Jar.Cookies(req.URL) {
			if cookie.Name == "__Host-openuem-csrf" {
				req.Header.Set("X-CSRF-Token", cookie.Value)
			}
		}
	}
	response, err := client.Do(req)
	if err != nil {
		return 0, "", ""
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 512<<10))
	if err != nil {
		t.Fatal("reference HTTP response could not be read")
	}
	return response.StatusCode, string(data), response.Header.Get("Location")
}

func TestReferenceAdministrator(t *testing.T) {
	fixture(t)
	client := client(t)
	ready := false
	lastStatus := 0
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		status, body, _ := request(t, client, "/login", nil)
		lastStatus = status
		if status == http.StatusOK && strings.Contains(body, `name="username"`) {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("private administrator source did not reach the actual console through the gateway (HTTP %d)", lastStatus)
	}
	const replacement = "Reference-Administrator-Replacement-Password-123!"
	if os.Getenv("OPENUEM_REFERENCE_RESTART") != "1" {
		password, err := keyfile.Read("/initial-password", 128)
		if err != nil {
			t.Fatal("initial administrator fixture password is unavailable")
		}
		defer clear(password)
		status, body, _ := request(t, client, "/login/userpass", url.Values{"username": {"first-admin"}, "password": {string(password)}})
		if status != http.StatusOK || !strings.Contains(body, "confirm-password") {
			t.Fatal("reference first login did not require password replacement")
		}
		status, body, _ = request(t, client, "/login/changepass", url.Values{"password": {replacement}, "confirm-password": {replacement}})
		if status != http.StatusOK || !strings.Contains(body, `name="username"`) {
			t.Fatal("reference administrator password replacement failed")
		}
	}
	status, _, location := request(t, client, "/login/userpass", url.Values{"username": {"first-admin"}, "password": {replacement}})
	if status != http.StatusFound || !strings.HasPrefix(location, "https://uem.example.test:8443/tenant/") || !strings.HasSuffix(location, "/dashboard") {
		t.Fatal("reference console did not accept the retained administrator password")
	}
}

func TestReferencePublicRoutes(t *testing.T) {
	fixture(t)
	client := client(t)
	if status, _, _ := request(t, client, "/login", nil); status != http.StatusForbidden {
		t.Fatal("unapproved source or forged forwarding headers reached administration")
	}
	for _, path := range []string{"/EnrollmentServer/Discovery.svc", "/enroll/desktop/bootstrap-keys"} {
		if status, _, _ := request(t, client, path, nil); status != http.StatusOK {
			t.Fatal("public native Windows or desktop listener is not routed through the gateway", path, status)
		}
	}
	status, _, _ := request(t, client, "/mdm/apple/enroll/"+strings.Repeat("A", 43), nil)
	if status != http.StatusNotFound && status != http.StatusGone {
		t.Fatal("public Apple listener did not reject an unknown enrollment through the gateway", status)
	}
}

func TestReferenceNetworkIsolation(t *testing.T) {
	fixture(t)
	addresses := strings.Split(os.Getenv("OPENUEM_REFERENCE_PRIVATE_TARGETS"), ",")
	if len(addresses) < 4 {
		t.Fatal("private network targets are incomplete")
	}
	for _, address := range addresses {
		connection, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		if err == nil {
			connection.Close()
			t.Fatal("public edge client reached a private backend socket")
		}
	}
}

type deviceRecord struct {
	ID string
	registry.Scope
}

func TestReferenceRegistry(t *testing.T) {
	fixture(t)
	dsn, err := servicecredentials.DatabaseURL("", "/run/database.url")
	if err != nil {
		t.Fatal("reference database credential is unavailable")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("reference database could not open")
	}
	defer db.Close()
	master, err := servicecredentials.EncryptionKey("", "/run/encryption.key")
	if err != nil {
		t.Fatal("reference registry key is unavailable")
	}
	store, err := registry.NewStore(db, master)
	if err != nil {
		t.Fatal("reference registry is unavailable")
	}
	ctx := t.Context()
	var record deviceRecord
	action := os.Getenv("OPENUEM_REFERENCE_ACTION")
	if action == "enroll" {
		if err := db.QueryRowContext(ctx, `SELECT tenant_sites,id FROM sites ORDER BY id LIMIT 1`).Scan(&record.TenantID, &record.SiteID); err != nil {
			t.Fatal("console did not initialize the reference organization and site")
		}
		if _, err = store.EnsureAuthority(ctx, record.TenantID, "Reference", "https://uem.example.test:8443", "first-admin", nil, nil); err != nil {
			t.Fatal("cannot initialize the synthetic organization enrollment authority")
		}
		invitation, err := store.Invite(ctx, registry.InvitationOptions{Scope: record.Scope, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "first-admin")
		if err != nil {
			t.Fatal("cannot create synthetic device invitation")
		}
		keys, err := enrollment.GenerateKeys()
		if err != nil {
			t.Fatal("cannot create synthetic endpoint keys")
		}
		defer keys.Broker.Wipe()
		claim, err := keys.Request(invitation.URL[strings.LastIndex(invitation.URL, "/")+1:], "windows", "amd64", "Reference endpoint")
		if err != nil {
			t.Fatal("synthetic endpoint key proof failed")
		}
		issued, err := store.Claim(ctx, *claim)
		if err != nil {
			t.Fatal("synthetic registry claim failed")
		}
		record.ID = issued.DeviceID
		seed, _ := keys.Broker.Seed()
		defer clear(seed)
		write(t, "/device/broker.seed", seed)
		encoded, _ := json.Marshal(record)
		write(t, "/device/record.json", encoded)
	} else {
		data, err := os.ReadFile("/device/record.json")
		if err != nil || json.Unmarshal(data, &record) != nil {
			t.Fatal("synthetic endpoint record is unavailable")
		}
	}
	if action == "enroll" || action == "inventory" {
		seed, err := keyfile.Read("/device/broker.seed", 512)
		if err != nil {
			t.Fatal("synthetic endpoint broker key is unavailable")
		}
		defer clear(seed)
		keys, err := nkeys.FromSeed(seed)
		if err != nil {
			t.Fatal("synthetic endpoint broker key is invalid")
		}
		defer keys.Wipe()
		public, err := keys.PublicKey()
		var scope registry.Scope
		var issuedKey string
		if err != nil || db.QueryRowContext(ctx, `SELECT tenant_id,site_id,broker_key FROM uem_agent_identities WHERE id=$1 AND revoked_at IS NULL`, record.ID).Scan(&scope.TenantID, &scope.SiteID, &issuedKey) != nil || scope != record.Scope || issuedKey != public {
			t.Fatal("synthetic inventory does not match the admitted endpoint identity")
		}
		// Inventory remains explicit fixture preparation. Public protocol issuance
		// does not prove native installed-agent reporting or hardware collection.
		orm := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
		if _, err := orm.Agent.Create().SetID(record.ID).SetOs("windows").SetHostname("Reference endpoint").SetIP("192.0.2.1").SetMAC("02:00:00:00:00:01").SetWan("192.0.2.1").AddSiteIDs(record.SiteID).Save(ctx); err != nil {
			t.Fatal("cannot prepare scoped synthetic agent inventory")
		}
	} else {
		orm := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
		count, err := orm.WingetConfigExclusion.Query().Where(wingetconfigexclusion.HasOwnerWith(agent.ID(record.ID))).Count(ctx)
		if err != nil || count != 1 {
			t.Fatal("scoped device request did not persist exactly one worker mutation")
		}
		if action == "revoke" {
			if store.RevokeIdentity(ctx, record.Scope, record.ID, "first-admin") != nil {
				t.Fatal("synthetic endpoint revocation failed")
			}
		} else if action != "verify" {
			t.Fatal("unknown reference registry action")
		}
	}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		var desired, complete bool
		err := db.QueryRowContext(ctx, `SELECT desired_active,revision=completed_revision FROM uem_agent_command_consumers WHERE device_id=$1`, record.ID).Scan(&desired, &complete)
		if err == nil && complete && desired == (action != "revoke") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("separate command provisioner did not reconcile the device consumer")
}

func TestReferenceDevice(t *testing.T) {
	fixture(t)
	var record deviceRecord
	data, err := os.ReadFile("/device/record.json")
	if err != nil || json.Unmarshal(data, &record) != nil {
		t.Fatal("synthetic endpoint record is unavailable")
	}
	seed, err := keyfile.Read("/device/broker.seed", 512)
	if err != nil {
		t.Fatal("synthetic endpoint key is unavailable")
	}
	defer clear(seed)
	key, err := nkeys.FromSeed(seed)
	if err != nil {
		t.Fatal("synthetic endpoint key is invalid")
	}
	defer key.Wipe()
	public, _ := key.PublicKey()
	inbox, _ := enrollment.ReplyPrefix(record.ID)
	closed := make(chan struct{})
	connection, err := nats.Connect("wss://uem.example.test:8443/agent-channel", nats.Nkey(public, key.Sign),
		nats.CustomInboxPrefix(inbox), nats.Secure(&tls.Config{RootCAs: roots(t)}), nats.NoReconnect(),
		nats.Timeout(5*time.Second), nats.ClosedHandler(func(*nats.Conn) { close(closed) }))
	if os.Getenv("OPENUEM_REFERENCE_ACTION") == "denied" {
		if err == nil {
			connection.Close()
			t.Fatal("revoked endpoint reconnected through the public gateway")
		}
		if !errors.Is(err, nats.ErrAuthorization) {
			t.Fatal("revoked endpoint did not receive an explicit broker authorization denial")
		}
		return
	}
	if err != nil {
		t.Fatal("individual endpoint did not authenticate through gateway WSS and the authorization service")
	}
	defer connection.Close()
	if os.Getenv("OPENUEM_REFERENCE_ACTION") == "connect" {
		return
	}
	subject, _ := enrollment.RequestSubject(record.ID, "wingetcfg.exclude")
	body, _ := json.Marshal(openuem.DeployAction{AgentId: record.ID, PackageId: "reference-fixture-package"})
	response, err := connection.Request(subject, body, 5*time.Second)
	if err != nil || len(response.Data) != 0 {
		t.Fatal("public endpoint request did not reach its authorized worker mutation")
	}
	if os.Getenv("OPENUEM_REFERENCE_ACTION") == "hold" {
		write(t, filepath.Join("/ready", "connected"), []byte("ready"))
		select {
		case <-closed:
		case <-time.After(30 * time.Second):
			t.Fatal("revocation did not disconnect the live public WSS session")
		}
	}
}

func TestReferenceHealth(t *testing.T) {
	fixture(t)
	client := &http.Client{Timeout: time.Second}
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		response, err := client.Get(os.Getenv("OPENUEM_REFERENCE_HEALTH_URL"))
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("private service health did not become ready")
}

func TestReferenceBrokerReady(t *testing.T) {
	fixture(t)
	seed, err := keyfile.Read("/run/broker.seed", 512)
	if err != nil {
		t.Fatal("private broker probe identity is unavailable")
	}
	defer clear(seed)
	key, err := nkeys.FromSeed(seed)
	if err != nil {
		t.Fatal("private broker probe identity is invalid")
	}
	defer key.Wipe()
	public, _ := key.PublicKey()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		connection, err := nats.Connect("tls://broker.internal:4222", nats.Nkey(public, key.Sign),
			nats.RootCAs("/run/backend-ca.pem"), nats.NoReconnect(), nats.Timeout(time.Second))
		if err == nil {
			connection.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("private broker did not become ready for an authenticated service")
}

// A command remains pending while the broker is upgraded. The fixture never
// dispatches this synthetic payload to a real agent or acknowledges it.
func TestReferencePendingCommand(t *testing.T) {
	fixture(t)
	var record deviceRecord
	data, err := os.ReadFile("/device/record.json")
	if err != nil || json.Unmarshal(data, &record) != nil {
		t.Fatal("pending command device is unavailable")
	}
	connect := func(path string) *nats.Conn {
		t.Helper()
		seed, err := keyfile.Read(path, 512)
		if err != nil {
			t.Fatal("pending command service identity is unavailable")
		}
		defer clear(seed)
		key, err := nkeys.FromSeed(seed)
		if err != nil {
			t.Fatal("pending command service identity is invalid")
		}
		defer key.Wipe()
		public, _ := key.PublicKey()
		connection, err := nats.Connect("tls://broker.internal:4222", nats.Nkey(public, key.Sign), nats.RootCAs("/run/backend-ca.pem"), nats.NoReconnect(), nats.Timeout(time.Second))
		if err != nil {
			t.Fatal("pending command service could not authenticate")
		}
		return connection
	}
	if os.Getenv("OPENUEM_REFERENCE_ACTION") == "publish" {
		connection := connect("/run/console.seed")
		defer connection.Close()
		js, err := jetstream.New(connection)
		if err != nil {
			t.Fatal("command publisher is unavailable")
		}
		if _, err := js.Publish(t.Context(), "agent.report."+record.ID, []byte("synthetic retained maintenance command")); err != nil {
			t.Fatal("synthetic command was not persisted")
		}
	}
	connection := connect("/run/provisioner.seed")
	defer connection.Close()
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal("command inspection is unavailable")
	}
	name, _ := enrollment.ConsumerName(record.ID)
	consumer, err := js.Consumer(t.Context(), "AGENTS_STREAM", name)
	if err != nil {
		t.Fatal("retained command consumer is missing")
	}
	info, err := consumer.Info(t.Context())
	if err != nil || info.NumPending != 1 {
		t.Fatal("maintenance lost the pending command")
	}
	stream, err := js.Stream(t.Context(), "AGENTS_STREAM")
	if err != nil {
		t.Fatal("retained command stream is missing")
	}
	state, err := stream.Info(t.Context())
	if err != nil || state.State.Msgs != 1 || state.State.LastSeq != 1 {
		t.Fatal("maintenance changed the retained stream message")
	}
}
