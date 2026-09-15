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

func exerciseAppleIKEv2Certificates(t *testing.T, h *Handler, ctx context.Context, tenant, site, otherTenant int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	path := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations", tenant, site)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(82), Subject: pkix.Name{CommonName: "Synthetic VPN trust"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	source := func(org int, scope, kind string) *apple.Profile {
		settings := map[string]any{"PayloadScope": scope, "URL": "https://ca.example.test/scep", "Keysize": 2048, "Challenge": "synthetic-vpn-console-secret", "CertificateData": der}
		data, err := apple.BuildProfile("VPN certificate <source>", "com.example.vpn-source."+uuid.NewString(), kind, settings)
		if err != nil {
			t.Fatal(err)
		}
		p, err := h.Apple.SaveProfile(ctx, org, "", 0, data, "organization-admin")
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	identity, trust := source(tenant, "System", "apple-scep"), source(tenant, "System", "apple-certificates")
	userIdentity, userTrust := source(tenant, "User", "apple-scep"), source(tenant, "User", "apple-certificates")
	// The preceding Wi-Fi route exercise seeds this organization's Apple settings.
	foreign := source(otherTenant, "System", "apple-scep")
	ref := func(p *apple.Profile) string { return p.ID + "/" + strconv.Itoa(p.Revision) }
	form := func() url.Values {
		return url.Values{"editor": {"vpn-ikev2-certificate"}, "name": {"Certificate <VPN>"}, "identifier": {"com.example.console-ikev2." + uuid.NewString()}, "payload_scope": {"System"}, "connection_name": {"Company VPN"}, "remote_address": {"vpn.example.test"}, "local_identifier": {"device.example.test"}, "remote_identifier": {"vpn.example.test"}, "authentication_mode": {"machine"}, "certificate_type": {"RSA"}, "server_issuer": {"Synthetic VPN issuer"}, "identity_revision": {ref(identity)}, "trust_revision": {ref(trust)}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", path, form()); rec.Code != 403 {
			t.Fatal("unprivileged VPN creation", user, rec.Code)
		}
		if rec := request(user, "GET", path, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "Create an IKEv2 certificate VPN profile") {
			t.Fatal("unprivileged VPN editor exposed", rec.Code)
		}
	}
	for _, bad := range []struct {
		key    string
		values []string
		status int
	}{
		{"csrf", []string{"wrong"}, 403}, {"confirmed", []string{""}, 400}, {"extra", []string{"synthetic-vpn-console-secret"}, 400},
		{"identity_revision", []string{ref(identity), ref(userIdentity)}, 400}, {"identity_revision", []string{identity.ID + "/01"}, 400}, {"identity_revision", []string{identity.ID + "/999"}, 404}, {"identity_revision", []string{ref(foreign)}, 404},
		{"identity_revision", []string{ref(trust)}, 400}, {"identity_revision", []string{ref(userIdentity)}, 400}, {"trust_revision", []string{""}, 400}, {"trust_revision", []string{ref(userTrust)}, 400}, {"trust_revision", []string{ref(identity)}, 400},
		{"payload_scope", []string{"invalid"}, 400}, {"connection_name", []string{""}, 400}, {"remote_address", []string{"https://vpn.example.test"}, 400}, {"local_identifier", []string{""}, 400}, {"authentication_mode", []string{"password"}, 400},
		{"certificate_type", []string{"ECDSA256"}, 400}, {"certificate_type", []string{""}, 400}, {"server_issuer", []string{""}, 400}, {"server_name", []string{"bad\nname"}, 400},
	} {
		f := form()
		f[bad.key] = bad.values
		if rec := request("organization-admin", "POST", path, f); rec.Code != bad.status || strings.Contains(rec.Body.String(), "synthetic-vpn-console-secret") {
			t.Fatal("invalid VPN form accepted or credential echoed", bad.key, rec.Code)
		}
	}
	if rec := request("organization-admin", "POST", path+"?trust_revision=existing", form()); rec.Code != 400 {
		t.Fatal("query overrode VPN trust", rec.Code)
	}
	updated := bytes.ReplaceAll(identity.Payload, []byte("synthetic-vpn-console-secret"), []byte("synthetic-new-vpn-secret"))
	if _, err = h.Apple.SaveProfile(ctx, tenant, identity.ID, 1, updated, "organization-admin"); err != nil {
		t.Fatal(err)
	}
	if err = h.Apple.DeleteProfile(ctx, tenant, identity.ID, "organization-admin"); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"system", "eap", "user", "existing"} {
		f := form()
		f.Set("identifier", "com.example.console-ikev2."+mode)
		if mode == "eap" {
			f.Set("authentication_mode", "eap-tls")
			f.Set("server_name", "vpn-certificate.example.test")
		}
		if mode == "user" {
			f.Set("payload_scope", "User")
			f.Set("identity_revision", ref(userIdentity))
			f.Set("trust_revision", ref(userTrust))
		}
		if mode == "existing" {
			f.Set("trust_revision", "existing")
		}
		if rec := request("organization-admin", "POST", path, f); rec.Code != 303 {
			t.Fatal("valid VPN form failed", mode, rec.Code)
		}
	}
	profiles, err := h.Apple.Profiles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range profiles {
		if !strings.HasPrefix(p.Identifier, "com.example.console-ikev2.") {
			continue
		}
		found++
		mode := strings.TrimPrefix(p.Identifier, "com.example.console-ikev2.")
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		payloads := root["PayloadContent"].([]any)
		vpn, identity := payloads[0].(map[string]any), payloads[1].(map[string]any)
		c := vpn["IKEv2"].(map[string]any)
		flag := uint64(0)
		if mode == "eap" {
			flag = 1
		}
		if p.Revision != 1 || vpn["UserDefinedName"] != "Company VPN" || c["PayloadCertificateUUID"] != identity["PayloadUUID"] || identity["PayloadContent"].(map[string]any)["Challenge"] != "synthetic-vpn-console-secret" || c["ExtendedAuthEnabled"] != flag {
			t.Fatal("VPN form changed exact credentials, mode or references")
		}
		if (p.Scope == "User") != (mode == "user") || (len(payloads) == 2) != (mode == "existing") {
			t.Fatal("VPN form changed scope or trust")
		}
		if mode == "eap" && (c["TLSMinimumVersion"] != "1.2" || c["TLSMaximumVersion"] != "1.2" || c["ServerCertificateCommonName"] != "vpn-certificate.example.test") {
			t.Fatal("EAP-TLS VPN settings lost")
		}
		if rec := request("scoped-viewer", "GET", path+"/"+p.ID+"/download", nil); rec.Code != 403 {
			t.Fatal("reader downloaded VPN credentials", rec.Code)
		}
		if rec := request("organization-admin", "GET", path+"/"+p.ID+"/download", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "synthetic-vpn-console-secret") {
			t.Fatal("authorized VPN download failed", rec.Code)
		}
	}
	if found != 4 {
		t.Fatal("unexpected VPN catalog mutations", found)
	}
	if rec := request("organization-admin", "GET", path, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Certificate &lt;VPN&gt;") || strings.Contains(rec.Body.String(), "synthetic-vpn-console-secret") {
		t.Fatal("VPN catalog leaked credentials or escaped incorrectly", rec.Code)
	}
}
