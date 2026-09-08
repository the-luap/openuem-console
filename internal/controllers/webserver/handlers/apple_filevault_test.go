package handlers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestFileVaultRoutesRequireDedicatedCapabilities(t *testing.T) {
	for path, want := range map[string]access.Capability{
		"/ios/:id/filevault":                  access.ManageDeviceSecurity,
		"/ios/:id/filevault/keys/:key/reveal": access.RetrieveRecoveryKeys,
		"/ios/:id/filevault/keys/:key/verify": access.ManageDeviceSecurity,
		"/ios/:id/filevault/keys/:key/rotate": access.ManageDeviceSecurity,
	} {
		for _, prefix := range []string{"", "/tenant/:tenant", "/tenant/:tenant/site/:site"} {
			if got, ok := appleCapability("POST", prefix+path); !ok || got != want {
				t.Fatal("wrong FileVault capability", got, ok)
			}
			for _, method := range []string{"GET", "HEAD", "PUT", "DELETE"} {
				if _, ok := appleCapability(method, prefix+path); ok {
					t.Fatal("unexpected FileVault method authorized", method)
				}
			}
		}
	}
}

func exerciseAppleFileVault(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	scope := apple.Scope{TenantID: tenant, SiteID: site}
	invite, err := h.Apple.Invite(ctx, scope, "Mac recovery console", "apple-console-admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_devices SET status='enrolled',model='Mac16,1',os_version='15.0',inventory_at=clock_timestamp(),security_at=clock_timestamp(),security_inventory='{"ManagementStatus":{"UserApprovedEnrollment":true},"FDE_Enabled":true}',certificate_expires_at=clock_timestamp()+interval '1 year' WHERE id=$1`, invite.DeviceID); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/tenant/%d/site/%d/ios/%s", tenant, site, invite.DeviceID)
	keyID := uuid.NewString()
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		for _, suffix := range []string{"/filevault", "/filevault/keys/" + keyID + "/reveal", "/filevault/keys/" + keyID + "/verify", "/filevault/keys/" + keyID + "/rotate"} {
			if rec := request(user, "POST", base+suffix, url.Values{"desired": {"enabled"}}); rec.Code != 403 {
				t.Fatal("unauthorized FileVault mutation", user, rec.Code)
			}
		}
	}
	if rec := request("organization-admin", "POST", base+"/filevault", url.Values{"desired": {"enabled"}, "csrf": {"wrong"}}); rec.Code != 403 {
		t.Fatal("FileVault ignored CSRF", rec.Code)
	}
	if rec := request("organization-admin", "POST", base+"/filevault", url.Values{"desired": {"enabled"}}); rec.Code != 303 {
		t.Fatal("FileVault setup failed", rec.Code, rec.Body.String())
	}
	var escrow string
	if err = h.Model.DB.QueryRowContext(ctx, `SELECT escrow_id FROM mdm_apple_filevault_policies WHERE device_id=$1`, invite.DeviceID).Scan(&escrow); err != nil {
		t.Fatal(err)
	}
	// Seed an encrypted recovery record under the console fixture's master key.
	// Native protocol tests separately exercise actual CMS ingestion end to end.
	plain := []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")
	master := sha256.Sum256([]byte("openuem/apple/secrets/v1\x00" + strings.Repeat("k", 32)))
	block, err := aes.NewCipher(master[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nonce, nonce, plain, []byte(fmt.Sprintf("%d/%s/%s/filevault_recovery_key", tenant, invite.DeviceID, keyID)))
	if _, err = h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_apple_filevault_keys(id,tenant_id,device_id,escrow_id,recovery_key) VALUES($1,$2,$3,$4,$5)`, keyID, tenant, invite.DeviceID, escrow, sealed); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_filevault_policies SET current_key_id=$2 WHERE device_id=$1`, invite.DeviceID, keyID); err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"organization-admin", "scoped-viewer", "scoped-operator"} {
		rec := request(user, "GET", base, nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), string(plain)) || !strings.Contains(rec.Body.String(), "Not yet validated against the Mac volume") {
			t.Fatal("unsafe FileVault device page", user, rec.Code)
		}
		if user != "organization-admin" && strings.Contains(rec.Body.String(), "Retrieve recovery key") {
			t.Fatal("key retrieval controls exposed to operator or viewer")
		}
		artifact("filevault-"+user, rec)
	}
	reveal := base + "/filevault/keys/" + keyID + "/reveal"
	for _, method := range []string{"GET", "HEAD"} {
		if rec := request("organization-admin", method, reveal, nil); rec.Code == 200 || strings.Contains(rec.Body.String(), string(plain)) {
			t.Fatal("read method disclosed recovery key")
		}
	}
	if rec := request("organization-admin", "POST", reveal, url.Values{"csrf": {"wrong"}}); rec.Code != 403 {
		t.Fatal("recovery disclosure ignored CSRF", rec.Code)
	}
	other := fmt.Sprintf("/tenant/%d/site/%d/ios/%s/filevault/keys/%s/reveal", tenant, sibling, invite.DeviceID, keyID)
	if rec := request("apple-console-admin", "POST", other, nil); rec.Code != 404 {
		t.Fatal("cross-site recovery disclosure", rec.Code)
	}
	rec := request("organization-admin", "POST", reveal, nil)
	if rec.Code != 200 || rec.Body.String() != string(plain) {
		t.Fatal("authorized recovery retrieval failed", rec.Code)
	}
	for header, part := range map[string]string{"Cache-Control": "no-store", "Content-Type": "text/plain", "Content-Security-Policy": "default-src 'none'", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"} {
		if !strings.Contains(rec.Header().Get(header), part) {
			t.Fatal("recovery response missing protection", header)
		}
	}
	var count int
	if err = h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_audit WHERE action='apple.filevault.key.reveal' AND resource_id=$1 AND details->>'site_id'=$2 AND actor='organization-admin'`, keyID, fmt.Sprint(site)).Scan(&count); err != nil || count != 1 {
		t.Fatal("recovery read audit missing", count, err)
	}
	exerciseFileVaultValidation(t, h, ctx, scope, invite.DeviceID, keyID, base, sibling, request, artifact)
}
