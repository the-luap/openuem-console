package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"mime/multipart"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func exercisePushRequestRoutes(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site, otherTenant, otherSite int) {
	t.Helper()
	t.Run("push requests use organization authority and explicit CSR association", func(t *testing.T) {
		defer h.SessionManager.Manager.Put(ctx, "uid", "apple-console-admin")
		base := fmt.Sprintf("/tenant/%d/site/%d", tenant, site)
		request := func(user, method, path, contentType string, body []byte) *httptest.ResponseRecorder {
			t.Helper()
			h.SessionManager.Manager.Put(ctx, "uid", user)
			h.SessionManager.Manager.Put(ctx, "usepasswd", false)
			req := httptest.NewRequest(method, path, bytes.NewReader(body)).WithContext(ctx)
			req.Header.Set("Content-Type", contentType)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			return rec
		}
		form := url.Values{"csrf": {"console-test-token"}, "organization": {"Request route test"}, "public_url": {"https://mdm.example.test"}, "apple_account": {`owner+<script>private-account</script>@example.test`}}
		reminderFingerprint := strings.Repeat("c", 64)
		if _, err := h.Model.DB.Exec(`INSERT INTO mdm_apple_push_reminders(id,tenant_id,fingerprint,expires_at,stage) VALUES('90000000-0000-0000-0000-000000000001',$1,$2,now(),0)`, tenant, reminderFingerprint); err != nil {
			t.Fatal(err)
		}
		post := func(user, path string) *httptest.ResponseRecorder {
			return request(user, "POST", path, "application/x-www-form-urlencoded", []byte(form.Encode()))
		}
		if rec := post("organization-admin", base+"/ios/setup/requests"); rec.Code != 400 {
			t.Fatal("missing confirmation accepted", rec.Code)
		}
		form.Set("confirmed", "yes")
		form.Set("csrf", "incorrect")
		if rec := post("organization-admin", base+"/ios/setup/requests"); rec.Code != 403 {
			t.Fatal("invalid CSRF accepted", rec.Code)
		}
		form.Set("csrf", "console-test-token")
		if rec := post("organization-admin", base+"/ios/setup/requests"); rec.Code != 303 {
			t.Fatal("organization admin create denied", rec.Code, rec.Body.String())
		}
		requests, err := h.Apple.PushRequests(ctx, tenant)
		if err != nil || len(requests) != 1 {
			t.Fatal("request missing", err)
		}
		id := requests[0].ID
		path := base + "/ios/setup/requests/" + id
		for _, user := range []string{"scoped-viewer", "scoped-operator"} {
			for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), base} {
				p := prefix + "/ios/setup/requests/" + id
				if rec := request(user, "GET", p+"/csr", "", nil); rec.Code != 403 {
					t.Fatal("scoped reader or operator downloaded CSR", user, rec.Code)
				}
				if rec := request(user, "GET", p+"/portal", "", nil); rec.Code != 403 {
					t.Fatal("scoped reader or operator downloaded vendor response", user, rec.Code)
				}
				for _, suffix := range []string{"/revoke", "/certificate", "/vendor"} {
					if rec := post(user, p+suffix); rec.Code != 403 {
						t.Fatal("scoped reader or operator reached mutation", user, suffix, rec.Code)
					}
				}
			}
			rec := request(user, "GET", base+"/ios/setup", "", nil)
			if rec.Code != 200 || strings.Contains(rec.Body.String(), id) || strings.Contains(rec.Body.String(), "private-account") || strings.Contains(rec.Body.String(), reminderFingerprint) || strings.Contains(rec.Body.String(), "Certificate expiry reminders") {
				t.Fatal("request metadata visible without certificate authority", rec.Code)
			}
		}
		rec := request("organization-admin", "GET", base+"/ios/setup", "", nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), id) || strings.Contains(rec.Body.String(), "<script>private-account</script>") || !strings.Contains(rec.Body.String(), "&lt;script&gt;") || !strings.Contains(rec.Body.String(), reminderFingerprint) || !strings.Contains(rec.Body.String(), "No eligible recipient") {
			t.Fatal("unsafe or missing request metadata", rec.Code)
		}
		if rec := request("apple-console-admin", "GET", fmt.Sprintf("/tenant/%d/ios/setup", otherTenant), "", nil); rec.Code != 200 || strings.Contains(rec.Body.String(), reminderFingerprint) {
			t.Fatal("reminder history crossed selected organization", rec.Code)
		}
		if rec := request("organization-admin", "GET", path+"/portal", "", nil); rec.Code != 503 {
			t.Fatal("unconfigured vendor download did not fail closed", rec.Code)
		}
		originalStore := h.Apple
		trust, err := apple.NewVendorTrust([]string{strings.Repeat("a", 64)})
		if err != nil {
			t.Fatal(err)
		}
		configuredStore, err := apple.NewStoreWithVendor(h.Model.DB, strings.Repeat("k", 32), trust)
		if err != nil {
			t.Fatal(err)
		}
		h.Apple = configuredStore
		defer func() { h.Apple = originalStore }()
		if rec := request("organization-admin", "GET", path+"/portal", "", nil); rec.Code != 404 {
			t.Fatal("missing signed request downloadable", rec.Code)
		}
		var vendorBody bytes.Buffer
		vendorWriter := multipart.NewWriter(&vendorBody)
		if err := vendorWriter.WriteField("csrf", "console-test-token"); err != nil {
			t.Fatal(err)
		}
		vendorPart, err := vendorWriter.CreateFormFile("vendor_request", "untrusted.plist")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = vendorPart.Write([]byte("untrusted vendor response")); err != nil {
			t.Fatal(err)
		}
		if err = vendorWriter.Close(); err != nil {
			t.Fatal(err)
		}
		badCSRF := bytes.ReplaceAll(vendorBody.Bytes(), []byte("console-test-token"), []byte("invalid-token"))
		if rec := request("organization-admin", "POST", path+"/vendor", vendorWriter.FormDataContentType(), badCSRF); rec.Code != 403 {
			t.Fatal("vendor upload accepted invalid CSRF", rec.Code)
		}
		if rec := request("organization-admin", "POST", path+"/vendor", vendorWriter.FormDataContentType(), vendorBody.Bytes()); rec.Code != 400 || strings.Contains(rec.Body.String(), "untrusted vendor response") {
			t.Fatal("invalid vendor upload was accepted or echoed", rec.Code)
		}
		h.Apple = originalStore
		foreignPath := fmt.Sprintf("/tenant/%d/site/%d/ios/setup/requests/%s/csr", otherTenant, otherSite, id)
		if rec := request("apple-console-admin", "GET", foreignPath, "", nil); rec.Code != 404 {
			t.Fatal("server admin crossed selected object scope", rec.Code)
		}
		rec = request("organization-admin", "GET", path+"/csr", "", nil)
		if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(rec.Header().Get("Content-Disposition"), id+".csr") {
			t.Fatal("CSR download headers", rec.Code, rec.Header())
		}
		block, rest := pem.Decode(rec.Body.Bytes())
		if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 || bytes.Contains(rec.Body.Bytes(), []byte("PRIVATE KEY")) {
			t.Fatal("CSR response is not public PKCS#10")
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			t.Fatal("CSR cannot be verified", err)
		}
		issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		// Synthetic local key/topic fixture; no Apple issuance or APNs claim.
		certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic route certificate", ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: requests[0].ExpectedTopic}}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 3, 2}, Value: []byte{5, 0}}}}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, csr.PublicKey, issuer)
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if err = writer.WriteField("csrf", "console-test-token"); err != nil {
			t.Fatal(err)
		}
		part, err := writer.CreateFormFile("push_certificate", "synthetic.pem")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = part.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
			t.Fatal(err)
		}
		if err = writer.Close(); err != nil {
			t.Fatal(err)
		}
		rec = request("organization-admin", "POST", path+"/certificate", writer.FormDataContentType(), body.Bytes())
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), apple.ErrPushCertificate.Error()) {
			t.Fatal("certificate-only import accepted an untrusted issuer", rec.Code, rec.Body.String())
		}
		if rec := request("organization-admin", "GET", path+"/csr", "", nil); rec.Code != 200 {
			t.Fatal("failed validation consumed request", rec.Code)
		}
		if rec := request("scoped-viewer", "GET", base+"/ios/setup", "", nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "private-account") {
			t.Fatal("active account metadata leaked to viewer", rec.Code)
		}
		if rec := post("organization-admin", base+"/ios/setup/requests"); rec.Code != 303 {
			t.Fatal("second request failed", rec.Code)
		}
		requests, err = h.Apple.PushRequests(ctx, tenant)
		if err != nil || len(requests) != 2 {
			t.Fatal(err)
		}
		if rec := post("organization-admin", base+"/ios/setup/requests/"+requests[0].ID+"/revoke"); rec.Code != 303 {
			t.Fatal("revoke route failed", rec.Code)
		}
	})
}
