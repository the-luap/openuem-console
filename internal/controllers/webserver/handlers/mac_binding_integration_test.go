package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/ent/release"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

// The protocol tests establish the two-channel proof. These router tests seed
// its receipts and reconcile against the complete Ent schema before checking
// grouping, historical aliases and action authority.
func exerciseMacConsole(t *testing.T, h *Handler, ctx context.Context, tenantID, siteID, siblingID int, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	if err := h.Apple.MigrateMacLinks(ctx); err != nil {
		t.Fatal(err)
	}
	scope := apple.Scope{TenantID: tenantID, SiteID: siteID}
	base := fmt.Sprintf("/tenant/%d/site/%d", tenantID, siteID)
	org := fmt.Sprintf("/tenant/%d", tenantID)
	seedMDM := func(name string) *apple.Invitation {
		t.Helper()
		invite, err := h.Apple.Invite(ctx, scope, name, "apple-console-admin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_devices SET status='enrolled',udid=id::text,model='Mac16,1',os_version='15.0',certificate_expires_at=clock_timestamp()+interval '1 year',inventory_at=clock_timestamp(),serial_number='CONSOLEMAC123' WHERE id=$1`, invite.DeviceID); err != nil {
			t.Fatal(err)
		}
		return invite
	}
	current := seedMDM("Canonical design Mac")
	old := seedMDM("Historical MDM Mac")
	invitation, err := h.Desktop.Registry.Invite(ctx, registry.InvitationOptions{Scope: registry.Scope{TenantID: tenantID, SiteID: siteID}, Platform: "macos", Architecture: "arm64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "apple-console-admin")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := keys.Request(invitation.URL[strings.LastIndex(invitation.URL, "/")+1:], "macos", "arm64", "Design agent")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.Desktop.Registry.Claim(ctx, *proof)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := h.Model.Client.Release.Create().SetVersion("0.11.0").SetReleaseType(release.ReleaseTypeAgent).SetOs("macos").SetArch("arm64").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Model.Client.Agent.Create().SetID(identity.DeviceID).SetRelease(installed).SetHostname("Agent duplicate Mac").SetNickname("Agent duplicate Mac").SetOs("macos").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(siteID).SetLastContact(time.Now()).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if err = h.Model.Client.OperatingSystem.Create().SetType("macos").SetVersion("15.0").SetDescription("macOS Sequoia").SetUsername("design").SetOwnerID(identity.DeviceID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err = h.Model.Client.Computer.Create().SetManufacturer("Apple").SetModel("Mac16,1").SetMemory(16000000000).SetProcessor("Apple").SetProcessorArch("arm64").SetProcessorCores(8).SetOwnerID(identity.DeviceID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	path := base + "/ios/" + current.DeviceID
	for _, prefix := range []string{"", org, base} {
		for _, suffix := range []string{"/mac-binding", "/mac-binding/cancel"} {
			if rec := request("scoped-viewer", "POST", prefix+"/ios/"+current.DeviceID+suffix, nil); rec.Code != 403 {
				t.Fatal("viewer reached channel mutation", rec.Code)
			}
		}
	}
	if rec := request("scoped-operator", "POST", path+"/mac-binding", url.Values{"csrf": {"wrong"}}); rec.Code != 403 {
		t.Fatal("verification accepted invalid CSRF", rec.Code)
	}
	if rec := request("scoped-operator", "POST", path+"/mac-binding", nil); rec.Code != 303 {
		t.Fatal("operator could not request verification", rec.Code, rec.Body.String())
	}
	rec := request("scoped-operator", "GET", path, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Cancel verification") {
		t.Fatal("pending challenge missing", rec.Code)
	}
	artifact("mac-binding-queued", rec)
	if rec = request("scoped-operator", "POST", path+"/mac-binding/cancel", nil); rec.Code != 303 {
		t.Fatal("cancel failed", rec.Code)
	}
	if err = h.Apple.RevokeEnrollment(ctx, scope, old.DeviceID, "apple-console-admin"); err != nil {
		t.Fatal(err)
	}
	// Seed the acknowledged profile and its hashed agent observation at the
	// protocol boundary; use the production reconciler against the real Ent
	// schema, including the legacy agents.oid and site_agents relations.
	if err = h.Apple.RequestMacBinding(ctx, scope, current.DeviceID, "apple-console-admin"); err != nil {
		t.Fatal(err)
	}
	binding, err := h.Apple.MacBinding(ctx, scope, current.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_mac_bindings SET status='installed',installed_at=clock_timestamp() WHERE id=$1`, binding.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='acknowledged',attempts=1 WHERE id=$1`, binding.CommandID); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_devices SET inventory='{"ProvisioningUDID":"00006001-001234567890ABCD"}'::jsonb WHERE id=$1`, current.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Model.DB.ExecContext(ctx, `INSERT INTO uem_agent_hardware(device_id,tenant_id,site_id,model,serial,platform_uuid,provisioning_udid,binding_challenge_id,binding_device_id,binding_token_hash) SELECT $1,tenant_id,site_id,'Mac16,1','CONSOLEMAC123','AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE','00006001-001234567890ABCD',id,device_id,token_hash FROM mdm_apple_mac_bindings WHERE id=$2`, identity.DeviceID, binding.ID); err != nil {
		t.Fatal(err)
	}
	if err = h.Apple.ReconcileMacLinks(ctx); err != nil {
		t.Fatal("association against the real Ent schema failed", err)
	}
	macs, err := h.Apple.MacDevices(ctx, scope)
	if err != nil || len(macs) != 1 {
		t.Fatal("canonical device missing from real schema", len(macs), err)
	}
	entity := macs[0].ID
	if _, err = h.Model.DB.ExecContext(ctx, `INSERT INTO uem_mac_mdm_channels(device_id,entity_id,tenant_id,site_id,retired_at) VALUES($1,$2,$3,$4,clock_timestamp())`, old.DeviceID, entity, tenantID, siteID); err != nil {
		t.Fatal(err)
	}
	canonical := base + "/mac/" + entity
	if _, err = h.Apple.MacDevice(ctx, scope, entity); err != nil {
		t.Fatal("canonical store read failed", err)
	}
	for _, user := range []string{"apple-console-admin", "organization-admin", "scoped-operator", "scoped-viewer"} {
		for _, filter := range []string{"", "macos", "apple"} {
			rec = request(user, "GET", base+"/devices?platform="+filter, nil)
			if rec.Code != 200 || strings.Count(rec.Body.String(), "Canonical design Mac") != 1 || strings.Contains(rec.Body.String(), "Agent duplicate Mac") || strings.Contains(rec.Body.String(), "Historical MDM Mac") || !strings.Contains(rec.Body.String(), canonical) {
				t.Fatal("canonical list did not group channels", user, filter, rec.Code)
			}
		}
		rec = request(user, "GET", canonical, nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Management channel history") || !strings.Contains(rec.Body.String(), old.DeviceID) || !strings.Contains(rec.Body.String(), identity.DeviceID) {
			t.Fatal("canonical detail or history missing", user, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "Open agent inventory and actions") != (user == "apple-console-admin") {
			t.Fatal("association changed legacy action permission", user)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("device metadata can be cached")
		}
		if user == "apple-console-admin" {
			artifact("mac-binding-linked", rec)
		}
		if user == "scoped-viewer" {
			artifact("mac-binding-viewer", rec)
		}
		for _, source := range []string{current.DeviceID, old.DeviceID} {
			for _, prefix := range []string{"", org, base} {
				rec = request(user, "GET", prefix+"/ios/"+source, nil)
				destination := rec.Header().Get("Location")
				if rec.Code != 303 || (destination != org+"/mac/"+entity && destination != canonical) {
					t.Fatal("historical read alias lost", user, prefix, rec.Code, rec.Header().Get("Location"))
				}
			}
		}
	}
	for _, p := range []string{fmt.Sprintf("/tenant/%d/site/%d/mac/%s", tenantID, siblingID, entity), base + "/mac/" + uuid.NewString()} {
		if rec = request("scoped-viewer", "GET", p, nil); rec.Code != 404 {
			t.Fatal("canonical identity crossed site or exposed existence", rec.Code)
		}
	}
	if err = h.Model.Client.Agent.UpdateOneID(identity.DeviceID).ClearRelease().Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if rec = request("apple-console-admin", "GET", canonical, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "Open agent inventory and actions") {
		t.Fatal("incomplete inventory exposed legacy actions", rec.Code)
	}
	if err = h.Model.Client.Agent.UpdateOneID(identity.DeviceID).SetRelease(installed).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if rec = request("apple-console-admin", "GET", base+"/computers/"+identity.DeviceID, nil); rec.Code != 200 {
		t.Fatal("canonical agent link does not open inventory", rec.Code, rec.Body.String())
	}
	if rec = request("scoped-viewer", "GET", base+"/computers/"+identity.DeviceID, nil); rec.Code != 403 {
		t.Fatal("canonical read granted legacy access", rec.Code)
	}
	var before int
	if err = h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, current.DeviceID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	rec = request("scoped-operator", "POST", base+"/ios/"+old.DeviceID+"/refresh", nil)
	if rec.Code == 303 {
		t.Fatal("historical mutation was redirected to the current channel")
	}
	var after int
	if err = h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, current.DeviceID).Scan(&after); err != nil || before != after {
		t.Fatal("historical action changed current enrollment", err)
	}
	if err = h.Model.Client.Agent.UpdateOneID(identity.DeviceID).ClearSite().AddSiteIDs(siblingID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	rec = request("apple-console-admin", "GET", canonical, nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "Open agent inventory and actions") {
		t.Fatal("moved legacy inventory retained a canonical action link", rec.Code)
	}
	if err = h.Model.Client.Agent.UpdateOneID(identity.DeviceID).ClearSite().AddSiteIDs(siteID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	ready := seedMDM("Browser verification Mac")
	artifact("mac-binding-ready", request("apple-console-admin", "GET", base+"/ios/"+ready.DeviceID, nil))
}
