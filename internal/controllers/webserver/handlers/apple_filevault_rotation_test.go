package handlers

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func exerciseFileVaultRotation(t *testing.T, h *Handler, ctx context.Context, scope apple.Scope, device, keyID, base, canonical string, sibling int, access *registry.AccessStore, identity *registry.Identity, recipient *enrollment.RecoveryRecipient, private *enrollment.RecoveryRecipientKey, cert *x509.Certificate, keys *enrollment.Keys, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	rotate := base + "/filevault/keys/" + keyID + "/rotate"
	for _, method := range []string{"GET", "HEAD"} {
		if rec := request("organization-admin", method, rotate, nil); rec.Code == 200 || rec.Code == 303 {
			t.Fatal("read method queued rotation")
		}
	}
	if rec := request("organization-admin", "POST", rotate, url.Values{"csrf": {"wrong"}}); rec.Code != 403 {
		t.Fatal("rotation ignored CSRF", rec.Code)
	}
	if rec := request("organization-admin", "POST", rotate, nil); rec.Code == 303 {
		t.Fatal("unconfirmed escrow admitted rotation")
	}
	var escrow, enable string
	if err := h.Model.DB.QueryRowContext(ctx, `SELECT e.id,e.enable_uuid FROM mdm_apple_filevault_policies p JOIN mdm_apple_filevault_escrow e ON e.id=p.escrow_id WHERE p.device_id=$1`, device).Scan(&escrow, &enable); err != nil {
		t.Fatal(err)
	}
	// Native protocol tests prove installation evidence. This HTTP fixture uses
	// its accepted profile state to test roles, CSRF, routing and the final page.
	profiles, _ := json.Marshal([]apple.InstalledProfile{
		{Identifier: "eu.openuem.filevault." + device + ".escrow", UUID: escrow, Managed: true, Payloads: []apple.InstalledPayload{{Type: "com.apple.security.FDERecoveryKeyEscrow"}}},
		{Identifier: "eu.openuem.filevault." + device + ".enable", UUID: enable, Managed: true, Payloads: []apple.InstalledPayload{{Type: "com.apple.MCX.FileVault2"}}},
	})
	if _, err := h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='cancelled' WHERE device_id=$1 AND filevault AND status IN ('queued','sent','not_now')`, device); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_filevault_policies SET phase='active',command_id=NULL,error='',recovery_error='',updated_at=clock_timestamp() WHERE device_id=$1`, device); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_devices SET installed_profiles=$2,profiles_at=clock_timestamp(),security_at=clock_timestamp(),security_inventory=jsonb_set(security_inventory,'{FDE_HasPersonalRecoveryKey}','true') WHERE id=$1`, device, profiles); err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"organization-admin", "scoped-viewer", "scoped-operator"} {
		rec := request(user, "GET", canonical, nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "Rotate current recovery key") != (user == "organization-admin") {
			t.Fatal("incorrect rotation controls", user, rec.Code)
		}
		artifact("filevault-rotation-"+user, rec)
	}
	foreign := fmt.Sprintf("/tenant/%d/site/%d/ios/%s/filevault/keys/%s/rotate", scope.TenantID, sibling, device, keyID)
	if rec := request("apple-console-admin", "POST", foreign, nil); rec.Code != 404 {
		t.Fatal("cross-site rotation accepted", rec.Code)
	}
	for range 2 {
		if rec := request("organization-admin", "POST", rotate, nil); rec.Code != 303 {
			t.Fatal("authorized rotation failed", rec.Code, rec.Body.String())
		}
	}
	rec := request("organization-admin", "GET", canonical, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Waiting for the Mac to replace") || strings.Contains(rec.Body.String(), "Rotate current recovery key") || strings.Contains(rec.Body.String(), "Remove management profiles") {
		t.Fatal("queued rotation state or blocked controls incorrect", rec.Code)
	}
	artifact("filevault-rotation-queued", rec)
	reply, err := access.HandleRotation(ctx, *identity, enrollment.RotationRequest{Version: enrollment.RotationVersion, Protocol: enrollment.RotationProtocol, AgentID: identity.ID, Action: "poll", RecipientID: recipient.ID})
	if err != nil || reply.Task == nil {
		t.Fatal("private rotation unavailable", err)
	}
	secret, err := private.OpenRotationTask(*reply.Task, recipient.Identity, recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	result, err := enrollment.NewRotationResult(reply.Task.Context, "rotated", secret.Nonce(), []byte("1111-2222-3333-4444-5555-6666"), cert, keys.Certificate, time.Now())
	secret.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = access.HandleRotation(ctx, *identity, enrollment.RotationRequest{Version: enrollment.RotationVersion, Protocol: enrollment.RotationProtocol, AgentID: identity.ID, Action: "result", Result: result}); err != nil {
		t.Fatal(err)
	}
	if err = h.Apple.ReconcileFileVaultRotations(ctx); err != nil {
		t.Fatal(err)
	}
	rec = request("organization-admin", "GET", canonical, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "New recovery key stored and validated") || strings.Contains(rec.Body.String(), "1111-2222-3333-4444-5555-6666") || strings.Contains(rec.Body.String(), "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF") {
		t.Fatal("rotation result missing or secret leaked", rec.Code)
	}
	artifact("filevault-rotation-complete", rec)
	var current string
	if err = h.Model.DB.QueryRowContext(ctx, `SELECT current_key_id FROM mdm_apple_filevault_policies WHERE device_id=$1`, device).Scan(&current); err != nil || current == keyID {
		t.Fatal("new key not escrowed", err)
	}
	for id, key := range map[string]string{keyID: "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF", current: "1111-2222-3333-4444-5555-6666"} {
		rec = request("organization-admin", "POST", base+"/filevault/keys/"+id+"/reveal", nil)
		if rec.Code != 200 || rec.Body.String() != key || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
			t.Fatal("rotated key history retrieval failed", rec.Code)
		}
	}
}
