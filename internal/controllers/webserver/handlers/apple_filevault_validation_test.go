package handlers

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func exerciseFileVaultValidation(t *testing.T, h *Handler, ctx context.Context, scope apple.Scope, device, keyID, base string, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	verify := base + "/filevault/keys/" + keyID + "/verify"
	for _, method := range []string{"GET", "HEAD"} {
		if rec := request("organization-admin", method, verify, nil); rec.Code == 200 || rec.Code == 303 {
			t.Fatal("read method queued private verification")
		}
	}
	if rec := request("organization-admin", "POST", verify, url.Values{"csrf": {"wrong"}}); rec.Code != 403 {
		t.Fatal("verification bypassed CSRF", rec.Code)
	}
	if rec := request("organization-admin", "POST", verify, nil); rec.Code == 303 {
		t.Fatal("native-only device queued agent validation")
	}
	invitation, err := h.Desktop.Registry.Invite(ctx, registry.InvitationOptions{Scope: registry.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, Platform: "macos", Architecture: "arm64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "apple-console-admin")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Broker.Wipe()
	claim, err := keys.Request(invitation.URL[strings.LastIndex(invitation.URL, "/")+1:], "macos", "arm64", "Recovery validation agent")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := h.Desktop.Registry.Claim(ctx, *claim)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Model.Client.Agent.Create().SetID(issued.DeviceID).SetHostname("Recovery validation Mac").SetOs("macos").AddSiteIDs(scope.SiteID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	access, err := registry.NewAccessStore(h.Model.DB)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := access.ActiveIdentity(ctx, issued.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	hardware := enrollment.HardwareInventory{Version: 1, AgentID: issued.DeviceID, Model: "Mac16,1", Serial: "VALIDATE123", PlatformUUID: strings.ToUpper(uuid.NewString()), ProvisioningUDID: "00006001-00ABCDEF12345678"}
	if err = access.RecordHardware(ctx, *identity, hardware); err != nil {
		t.Fatal(err)
	}
	// The native association tests establish the two-channel proof. This router
	// fixture seeds its accepted association to exercise the full Ent schema.
	entity := uuid.NewString()
	if _, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_devices SET serial_number=$2,inventory=jsonb_build_object('ProvisioningUDID',$3::text),inventory_at=clock_timestamp() WHERE id=$1`, device, hardware.Serial, hardware.ProvisioningUDID); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Model.DB.ExecContext(ctx, `INSERT INTO uem_mac_devices(id,tenant_id,site_id,model,serial,platform_uuid,provisioning_udid) VALUES($1,$2,$3,$4,$5,$6,$7)`, entity, scope.TenantID, scope.SiteID, hardware.Model, hardware.Serial, hardware.PlatformUUID, hardware.ProvisioningUDID); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Model.DB.ExecContext(ctx, `INSERT INTO uem_mac_mdm_channels(device_id,entity_id,tenant_id,site_id) VALUES($1,$2,$3,$4)`, device, entity, scope.TenantID, scope.SiteID); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Model.DB.ExecContext(ctx, `INSERT INTO uem_mac_agent_channels(device_id,entity_id,tenant_id,site_id) VALUES($1,$2,$3,$4)`, issued.DeviceID, entity, scope.TenantID, scope.SiteID); err != nil {
		t.Fatal(err)
	}
	private, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer private.Close()
	response, err := access.HandleRecovery(ctx, *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "challenge", PublicKey: private.PublicKey()})
	if err != nil || response.Registration == nil {
		t.Fatal("recipient challenge failed", err)
	}
	block, _ := pem.Decode([]byte(issued.Certificate))
	if block == nil {
		t.Fatal("missing signing certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := enrollment.SignRecoveryRegistration(*response.Registration, cert, keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response, err = access.HandleRecovery(ctx, *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "register", Registration: response.Registration, Signature: signature})
	if err != nil || response.Recipient == nil {
		t.Fatal("recipient registration failed", err)
	}
	recipient := response.Recipient
	canonical := fmt.Sprintf("/tenant/%d/site/%d/mac/%s", scope.TenantID, scope.SiteID, entity)
	for _, user := range []string{"organization-admin", "scoped-viewer", "scoped-operator"} {
		rec := request(user, "GET", canonical, nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF") {
			t.Fatal("unsafe validation page", user, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "Validate current recovery key") != (user == "organization-admin") {
			t.Fatal("incorrect validation controls", user)
		}
		artifact("filevault-validation-"+user, rec)
	}
	foreign := fmt.Sprintf("/tenant/%d/site/%d/ios/%s/filevault/keys/%s/verify", scope.TenantID, sibling, device, keyID)
	if rec := request("apple-console-admin", "POST", foreign, nil); rec.Code != 404 {
		t.Fatal("cross-site validation accepted", rec.Code)
	}
	for range 2 {
		if rec := request("organization-admin", "POST", verify, nil); rec.Code != 303 || strings.Contains(rec.Body.String(), "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF") {
			t.Fatal("validation queue failed", rec.Code, rec.Body.String())
		}
	}
	rec := request("organization-admin", "GET", canonical, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Waiting for the Mac to validate") || strings.Contains(rec.Body.String(), "Validate current recovery key") {
		t.Fatal("queued validation state missing", rec.Code)
	}
	artifact("filevault-validation-queued", rec)
	var count int
	if err = h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_filevault_validations WHERE device_id=$1`, device).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate form submission created tasks", err)
	}
	for _, outcome := range []string{"valid", "invalid"} {
		if outcome == "invalid" {
			if rec = request("organization-admin", "POST", verify, nil); rec.Code != 303 {
				t.Fatal("revalidation failed", rec.Code)
			}
		}
		response, err = access.HandleRecovery(ctx, *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "poll", RecipientID: recipient.ID})
		if err != nil || response.Task == nil {
			t.Fatal("task delivery failed", err)
		}
		secret, err := private.Open(*response.Task, recipient.Identity, recipient.ID, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(secret.Key(), []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) {
			t.Fatal("router changed escrow key")
		}
		result, err := secret.Result(outcome, cert, keys.Certificate, time.Now())
		secret.Close()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = access.HandleRecovery(ctx, *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "result", Result: result}); err != nil {
			t.Fatal(err)
		}
		if _, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_filevault_validations SET next_check_at=clock_timestamp() WHERE device_id=$1`, device); err != nil {
			t.Fatal(err)
		}
		if err = h.Apple.ReconcileFileVaultValidations(ctx); err != nil {
			t.Fatal(err)
		}
		rec = request("organization-admin", "GET", canonical, nil)
		message := "Validated on"
		if outcome == "invalid" {
			message = "does not unlock its volume"
		}
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), message) || strings.Contains(rec.Body.String(), "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF") {
			t.Fatal("signed result missing from device page", outcome, rec.Code)
		}
		artifact("filevault-validation-"+outcome, rec)
	}
}
