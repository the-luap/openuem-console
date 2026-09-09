package handlers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"howett.net/plist"
)

func exerciseAppleWiFiEAPTLS(t *testing.T, h *Handler, ctx context.Context, tenant, site, otherTenant int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	path := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations", tenant, site)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(81), Subject: pkix.Name{CommonName: "Synthetic RADIUS trust"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	source := func(org int, scope, kind string) *apple.Profile {
		settings := map[string]any{"PayloadScope": scope, "URL": "https://ca.example.test/scep", "Keysize": 2048, "Challenge": "synthetic-wifi-console-secret", "CertificateData": der}
		data, err := apple.BuildProfile("Certificate <source>", "com.example.console-source."+uuid.NewString(), kind, settings)
		if err != nil {
			t.Fatal(err)
		}
		p, err := h.Apple.SaveProfile(ctx, org, "", 0, data, "organization-admin")
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	identity := source(tenant, "System", "apple-scep")
	trust := source(tenant, "System", "apple-certificates")
	userIdentity := source(tenant, "User", "apple-scep")
	userTrust := source(tenant, "User", "apple-certificates")
	foreign := source(otherTenant, "System", "apple-scep")
	ref := func(p *apple.Profile) string { return p.ID + "/" + strconv.Itoa(p.Revision) }
	form := func() url.Values {
		return url.Values{"editor": {"wifi-eap-tls"}, "name": {"Enterprise <network>"}, "identifier": {"com.example.console-enterprise." + uuid.NewString()}, "payload_scope": {"System"}, "ssid": {" Company café "}, "wifi_security": {"WPA2"}, "tls_minimum": {"1.2"}, "tls_maximum": {"1.2"}, "server_names": {"radius.example.test\nwpa.*.example.test"}, "auto_join": {"false"}, "hidden_network": {"true"}, "identity_revision": {ref(identity)}, "trust_revision": {ref(trust)}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", path, form()); rec.Code != 403 {
			t.Fatal("unprivileged enterprise Wi-Fi creation", user, rec.Code)
		}
		if rec := request(user, "GET", path, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "Create an enterprise Wi-Fi profile") {
			t.Fatal("unprivileged enterprise Wi-Fi editor exposed", rec.Code)
		}
	}
	for _, bad := range []struct {
		key    string
		values []string
		status int
	}{
		{"csrf", []string{"wrong"}, 403}, {"confirmed", []string{""}, 400}, {"extra", []string{"unapproved"}, 400},
		{"identity_revision", []string{ref(identity), ref(userIdentity)}, 400}, {"identity_revision", []string{identity.ID + "/01"}, 400}, {"identity_revision", []string{identity.ID + "/-1"}, 400}, {"identity_revision", []string{identity.ID + "/2147483648"}, 400}, {"identity_revision", []string{"AAAAAAAA-0000-4000-8000-000000000001/1"}, 400}, {"identity_revision", []string{identity.ID + "/999"}, 404}, {"identity_revision", []string{ref(foreign)}, 404}, {"identity_revision", []string{ref(trust)}, 400}, {"identity_revision", []string{ref(userIdentity)}, 400},
		{"trust_revision", []string{""}, 400}, {"trust_revision", []string{ref(identity)}, 400}, {"trust_revision", []string{ref(userTrust)}, 400}, {"payload_scope", []string{"invalid"}, 400}, {"ssid", []string{strings.Repeat("é", 17)}, 400}, {"wifi_security", []string{"None"}, 400}, {"auto_join", []string{"yes"}, 400}, {"hidden_network", []string{"true", "false"}, 400}, {"tls_minimum", []string{"1.3"}, 400}, {"server_names", []string{"*"}, 400},
	} {
		f := form()
		f[bad.key] = bad.values
		if rec := request("organization-admin", "POST", path, f); rec.Code != bad.status || strings.Contains(rec.Body.String(), "synthetic-wifi-console-secret") {
			t.Fatal("invalid enterprise Wi-Fi form accepted or secret echoed", bad.key, rec.Code)
		}
	}
	if rec := request("organization-admin", "POST", path+"?trust_revision=existing", form()); rec.Code != 400 {
		t.Fatal("query changed Wi-Fi certificate trust", rec.Code)
	}
	// The console submits a retained revision, including when its catalog entry
	// changes while the operator reviews the form.
	updated := bytes.ReplaceAll(identity.Payload, []byte("synthetic-wifi-console-secret"), []byte("synthetic-new-console-secret"))
	if _, err = h.Apple.SaveProfile(ctx, tenant, identity.ID, 1, updated, "organization-admin"); err != nil {
		t.Fatal(err)
	}
	if err = h.Apple.DeleteProfile(ctx, tenant, identity.ID, "organization-admin"); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"system", "existing", "user", "tls13"} {
		f := form()
		f.Set("identifier", "com.example.console-enterprise."+mode)
		if mode == "existing" {
			f.Set("trust_revision", "existing")
		}
		if mode == "user" {
			f.Set("payload_scope", "User")
			f.Set("identity_revision", ref(userIdentity))
			f.Set("trust_revision", ref(userTrust))
		}
		if mode == "tls13" {
			f.Set("tls_minimum", "1.3")
			f.Set("tls_maximum", "1.3")
			f.Set("outer_identity", "anonymous@example.test")
		}
		if rec := request("organization-admin", "POST", path, f); rec.Code != 303 {
			t.Fatal("enterprise Wi-Fi creation failed", mode, rec.Code)
		}
	}
	profiles, err := h.Apple.Profiles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range profiles {
		if !strings.HasPrefix(p.Identifier, "com.example.console-enterprise.") {
			continue
		}
		found++
		mode := strings.TrimPrefix(p.Identifier, "com.example.console-enterprise.")
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		payloads := root["PayloadContent"].([]any)
		wifi := payloads[0].(map[string]any)
		copied := payloads[1].(map[string]any)
		eap := wifi["EAPClientConfiguration"].(map[string]any)
		if p.Revision != 1 || wifi["SSID_STR"] != " Company café " || wifi["AutoJoin"] != false || wifi["HIDDEN_NETWORK"] != true || wifi["PayloadCertificateUUID"] != copied["PayloadUUID"] || copied["PayloadContent"].(map[string]any)["Challenge"] != "synthetic-wifi-console-secret" || eap["AcceptEAPTypes"].([]any)[0] != uint64(13) {
			t.Fatal("Wi-Fi composition changed credentials, revision, references or wire types")
		}
		if (p.Scope == "User") != (mode == "user") || (len(payloads) == 2) != (mode == "existing") {
			t.Fatal("Wi-Fi scope or explicit trust choice changed")
		}
		if mode == "tls13" && (eap["OuterIdentity"] != "anonymous@example.test" || eap["TLSMinimumVersion"] != "1.3") {
			t.Fatal("TLS 1.3 outer identity lost")
		}
		if rec := request("scoped-viewer", "GET", path+"/"+p.ID+"/download", nil); rec.Code != 403 {
			t.Fatal("reader downloaded composed credentials", rec.Code)
		}
		if rec := request("organization-admin", "GET", path+"/"+p.ID+"/download", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "synthetic-wifi-console-secret") {
			t.Fatal("authorized composed profile download unavailable", rec.Code)
		}
	}
	if found != 4 {
		t.Fatal("unexpected enterprise Wi-Fi catalog mutations", found)
	}
	if rec := request("organization-admin", "GET", path, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Enterprise &lt;network&gt;") || !strings.Contains(rec.Body.String(), "Certificate &lt;source&gt;") || strings.Contains(rec.Body.String(), "synthetic-wifi-console-secret") {
		t.Fatal("Wi-Fi catalog escaped incorrectly or exposed secret", rec.Code)
	}
	var count int
	if err = h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_audit WHERE action='apple.profile.compose' AND tenant_id=$1`, tenant).Scan(&count); err != nil || count != 4 {
		t.Fatal("composition audit missing", count, err)
	}
}
