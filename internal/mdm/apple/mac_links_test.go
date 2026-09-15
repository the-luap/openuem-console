package apple

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"howett.net/plist"
)

func enrollMacAgent(t *testing.T, r *registry.Store, scope registry.Scope) *registry.Identity {
	t.Helper()
	if _, err := r.EnsureAuthority(t.Context(), scope.TenantID, "Test organization", "https://uem.example.test", "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	invite, err := r.Invite(t.Context(), registry.InvitationOptions{Scope: scope, Platform: "macos", Architecture: "arm64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	req, err := keys.Request(invite.URL[strings.LastIndex(invite.URL, "/")+1:], "macos", "arm64", "Individual Mac")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := r.Claim(t.Context(), *req)
	if err != nil {
		t.Fatal(err)
	}
	return &registry.Identity{ID: issued.DeviceID, Scope: scope, Platform: "macos", Architecture: "arm64", DisplayName: "Individual Mac", CertificateExpiresAt: time.Now().Add(time.Hour)}
}

func deliverMacProof(t *testing.T, s *Store, d *Device) *enrollment.MacBindingProof {
	t.Helper()
	if err := s.RequestMacBinding(t.Context(), Scope{TenantID: d.TenantID, SiteID: d.SiteID}, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	data, err := s.Connect(t.Context(), d, map[string]any{"Status": "Idle", "UDID": d.UDID})
	if err != nil {
		t.Fatal(err)
	}
	command, body := bindingCommand(t, data, "InstallProfile")
	var profile map[string]any
	if _, err = plist.Unmarshal(body["Payload"].([]byte), &profile); err != nil {
		t.Fatal(err)
	}
	payload := profile["PayloadContent"].([]any)[0].(map[string]any)
	domain := payload["PayloadContent"].(map[string]any)[enrollment.MacBindingDomain].(map[string]any)
	settings := domain["Forced"].([]any)[0].(map[string]any)["mcx_preference_settings"].(map[string]any)
	proof := &enrollment.MacBindingProof{ChallengeID: stringValue(settings, "ChallengeID"), DeviceID: stringValue(settings, "DeviceID"), Token: stringValue(settings, "Token")}
	if !proof.Valid() {
		t.Fatal("invalid issued binding proof")
	}
	if _, err = s.Connect(t.Context(), d, map[string]any{"Status": "Acknowledged", "UDID": d.UDID, "CommandUUID": command}); err != nil {
		t.Fatal(err)
	}
	return proof
}

func recordMacProof(t *testing.T, s *Store, i *registry.Identity, proof *enrollment.MacBindingProof) enrollment.HardwareInventory {
	t.Helper()
	access, err := registry.NewAccessStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	h := enrollment.HardwareInventory{Version: 1, AgentID: i.ID, Model: "Mac16,1", Serial: "ABCD123456", PlatformUUID: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", ProvisioningUDID: "00006001-001234567890ABCD", Binding: proof}
	if err = access.RecordHardware(t.Context(), *i, h); err != nil {
		t.Fatal(err)
	}
	return h
}

func acknowledgeMacCleanup(t *testing.T, s *Store, d *Device) {
	t.Helper()
	data, err := s.Connect(t.Context(), d, map[string]any{"Status": "Idle", "UDID": d.UDID})
	if err != nil {
		t.Fatal(err)
	}
	command, _ := bindingCommand(t, data, "RemoveProfile")
	if _, err = s.Connect(t.Context(), d, map[string]any{"Status": "Acknowledged", "UDID": d.UDID, "CommandUUID": command}); err != nil {
		t.Fatal(err)
	}
}

func TestMacChannelsLinkOnlyAfterBothAuthenticatedProofs(t *testing.T) {
	s, d, r := macBindingFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	agent := enrollMacAgent(t, r, registry.Scope{TenantID: 1, SiteID: 1})
	recordMacProof(t, s, agent, nil)
	if err := s.ReconcileMacLinks(t.Context()); err != nil {
		t.Fatal(err)
	}
	devices, err := s.MacDevices(t.Context(), scope)
	if err != nil || len(devices) != 0 {
		t.Fatal("hardware alone linked channels", err)
	}
	proof := deliverMacProof(t, s, d)
	recordMacProof(t, s, agent, proof)
	if err = s.ReconcileMacLinks(t.Context()); err != nil {
		t.Fatal(err)
	}
	devices, err = s.MacDevices(t.Context(), scope)
	if err != nil || len(devices) != 1 || devices[0].MDMID != d.ID || devices[0].AgentID != agent.ID || devices[0].AgentStatus != "enrolled" {
		t.Fatal("verified channels not grouped", devices, err)
	}
	entity := devices[0].ID
	b, err := s.MacBinding(t.Context(), scope, d.ID)
	if err != nil || b.Status != "consumed" || b.CleanupAt != nil {
		t.Fatal("proof consumption lost", err)
	}
	detail, err := s.MacDevice(t.Context(), scope, entity)
	if err != nil || len(detail.History) != 2 {
		t.Fatal("channel history missing", err)
	}
	foreign, err := s.MacDevices(t.Context(), Scope{TenantID: 2})
	if err != nil || len(foreign) != 0 {
		t.Fatal("canonical device crossed organization", err)
	}
	if _, err = s.MacDevice(t.Context(), Scope{TenantID: 1, SiteID: 2}, entity); !errors.Is(err, ErrNotFound) {
		t.Fatal("canonical detail crossed site", err)
	}
	mdmAliases, agentAliases, err := s.MacAliases(t.Context(), scope)
	if err != nil || mdmAliases[d.ID] != entity || agentAliases[agent.ID] != entity {
		t.Fatal("source aliases missing", err)
	}
	var auditSite int
	if err = s.db.QueryRow(`SELECT (details->>'site_id')::int FROM mdm_apple_audit WHERE action='apple.mac.channels.link' AND resource_id=$1`, entity).Scan(&auditSite); err != nil || auditSite != 1 {
		t.Fatal("link audit lost site attribution", err)
	}
	acknowledgeMacCleanup(t, s, d)
	recordMacProof(t, s, agent, nil)
	if err = s.ReconcileMacLinks(t.Context()); err != nil {
		t.Fatal(err)
	}
	devices, err = s.MacDevices(t.Context(), scope)
	if err != nil || len(devices) != 1 || devices[0].ID != entity {
		t.Fatal("consumed proof removal discarded stable identity", err)
	}
	if err = s.MigrateMacLinks(t.Context()); err != nil {
		t.Fatal("link migration replay failed", err)
	}
}

func TestMacReenrollmentRetainsCanonicalIdentityAndHistoricalAliases(t *testing.T) {
	for _, replace := range []string{"agent", "mdm", "both"} {
		t.Run(replace, func(t *testing.T) {
			s, d, r := macBindingFixture(t)
			scope := Scope{TenantID: 1, SiteID: 1}
			agentScope := registry.Scope{TenantID: 1, SiteID: 1}
			agent := enrollMacAgent(t, r, agentScope)
			proof := deliverMacProof(t, s, d)
			recordMacProof(t, s, agent, proof)
			if err := s.ReconcileMacLinks(t.Context()); err != nil {
				t.Fatal(err)
			}
			devices, err := s.MacDevices(t.Context(), scope)
			if err != nil || len(devices) != 1 {
				t.Fatal(err)
			}
			entity, oldMDM, oldAgent := devices[0].ID, d.ID, agent.ID
			acknowledgeMacCleanup(t, s, d)
			if replace == "agent" || replace == "both" {
				if err = r.RevokeIdentity(t.Context(), agentScope, agent.ID, "admin"); err != nil {
					t.Fatal(err)
				}
				agent = enrollMacAgent(t, r, agentScope)
			}
			if replace == "mdm" || replace == "both" {
				if err = s.RevokeEnrollment(t.Context(), scope, d.ID, "admin"); err != nil {
					t.Fatal(err)
				}
				d, _, _ = testEnrollPlatformWithKey(t, s, scope, "Reenrolled Mac", "Mac16,1", "15.0")
				drainMacHardwareInventory(t, s, d, map[string]any{"SerialNumber": "ABCD123456", "ProvisioningUDID": "00006001-001234567890ABCD"})
			}
			proof = deliverMacProof(t, s, d)
			recordMacProof(t, s, agent, proof)
			if err = s.ReconcileMacLinks(t.Context()); err != nil {
				t.Fatal(err)
			}
			devices, err = s.MacDevices(t.Context(), scope)
			if err != nil || len(devices) != 1 || devices[0].ID != entity || devices[0].MDMID != d.ID || devices[0].AgentID != agent.ID {
				t.Fatal("reenrollment duplicated or replaced canonical identity", devices, err)
			}
			mdmAliases, agentAliases, err := s.MacAliases(t.Context(), scope)
			if err != nil || mdmAliases[oldMDM] != entity || agentAliases[oldAgent] != entity || mdmAliases[d.ID] != entity || agentAliases[agent.ID] != entity {
				t.Fatal("reenrollment lost old read links", err)
			}
			detail, err := s.MacDevice(t.Context(), scope, entity)
			want := 3
			if replace == "both" {
				want = 4
			}
			if err != nil || len(detail.History) != want {
				t.Fatal("reenrollment lost channel history", err)
			}
		})
	}
}

func TestMacLinkConflictsAndAuditFailureDoNotPartiallyAttachChannels(t *testing.T) {
	for _, scenario := range []string{"active_agent", "hardware", "multiple", "audit", "expired", "revoked"} {
		t.Run(scenario, func(t *testing.T) {
			s, d, r := macBindingFixture(t)
			scope := Scope{TenantID: 1, SiteID: 1}
			agentScope := registry.Scope{TenantID: 1, SiteID: 1}
			first := enrollMacAgent(t, r, agentScope)
			proof := deliverMacProof(t, s, d)
			recordMacProof(t, s, first, proof)
			if scenario == "active_agent" {
				if err := s.ReconcileMacLinks(t.Context()); err != nil {
					t.Fatal(err)
				}
				acknowledgeMacCleanup(t, s, d)
				proof = deliverMacProof(t, s, d)
				next := enrollMacAgent(t, r, agentScope)
				recordMacProof(t, s, next, proof)
			}
			if scenario == "hardware" {
				if _, err := s.db.Exec(`UPDATE uem_agent_hardware SET serial='CONFLICT123' WHERE device_id=$1`, first.ID); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "multiple" {
				second := enrollMacAgent(t, r, agentScope)
				recordMacProof(t, s, second, proof)
			}
			if scenario == "audit" {
				if _, err := s.db.Exec(`ALTER TABLE mdm_apple_audit ADD CONSTRAINT link_audit_failure CHECK(action <> 'apple.mac.channels.link') NOT VALID`); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "expired" {
				if _, err := s.db.Exec(`UPDATE mdm_apple_mac_bindings SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, proof.ChallengeID); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "revoked" {
				if err := r.RevokeIdentity(t.Context(), agentScope, first.ID, "admin"); err != nil {
					t.Fatal(err)
				}
			}
			err := s.ReconcileMacLinks(t.Context())
			if (err != nil) != (scenario == "audit") {
				t.Fatal("unexpected reconciliation error", err)
			}
			devices, err := s.MacDevices(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "active_agent" {
				if len(devices) != 1 || devices[0].AgentID != first.ID {
					t.Fatal("active agent was silently replaced")
				}
			} else if len(devices) != 0 {
				t.Fatal("rejected evidence created a canonical device")
			}
			var retired int
			if err = s.db.QueryRow(`SELECT count(*) FROM uem_mac_agent_channels WHERE retired_at IS NOT NULL`).Scan(&retired); err != nil || retired != 0 {
				t.Fatal("conflict partially retired a channel", err)
			}
			b, err := s.MacBinding(t.Context(), scope, d.ID)
			if err != nil {
				t.Fatal(err)
			}
			if (scenario == "hardware" || scenario == "multiple" || scenario == "active_agent") && b.Status != "conflict" {
				t.Fatal("conflict not explained")
			}
			if scenario == "audit" && b.Status != "installed" {
				t.Fatal("audit failure consumed proof")
			}
		})
	}
}

func TestMacHardwareComparisonDistinguishesIntelAndAppleSilicon(t *testing.T) {
	now := time.Now()
	intel, silicon := false, true
	h := enrollment.HardwareInventory{Version: 1, AgentID: "10000000-0000-4000-8000-000000000001", Model: "MacBookPro16,1", Serial: "ABCD123456", PlatformUUID: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"}
	d := Device{Status: "enrolled", Model: h.Model, SerialNumber: h.Serial, UDID: h.PlatformUUID, AppleSilicon: &intel, InventoryAt: &now, CertificateExpiresAt: now.Add(time.Hour)}
	if !macHardwareMatches(&d, h, now) {
		t.Fatal("explicit Intel hardware evidence was rejected")
	}
	for _, indicator := range []*bool{nil, &silicon} {
		d.AppleSilicon = indicator
		if macHardwareMatches(&d, h, now) {
			t.Fatal("unknown or silicon MDM UDID was treated as platform UUID")
		}
	}
	d.AppleSilicon = &silicon
	d.Inventory = map[string]any{"ProvisioningUDID": "00006001-001234567890ABCD"}
	h.ProvisioningUDID = "00006001-001234567890ABCD"
	if !macHardwareMatches(&d, h, now) {
		t.Fatal("provisioning identifier was not used")
	}
	h.ProvisioningUDID = "00006001-001234567890FFFF"
	if macHardwareMatches(&d, h, now) {
		t.Fatal("different provisioning identifiers matched")
	}
	h.ProvisioningUDID = "00006001-001234567890ABCD"
	old := now.Add(-25 * time.Hour)
	d.InventoryAt = &old
	if macHardwareMatches(&d, h, now) {
		t.Fatal("stale MDM inventory was accepted")
	}
}

func TestMacLinksRecheckEvidenceAfterConcurrentIdentityLock(t *testing.T) {
	for _, scenario := range []string{"cleared_competitor", "revoked", "agent_expired", "challenge_expired", "wrong_hash", "foreign_site"} {
		t.Run(scenario, func(t *testing.T) {
			s, d, r := macBindingFixture(t)
			agent := enrollMacAgent(t, r, registry.Scope{TenantID: 1, SiteID: 1})
			proof := deliverMacProof(t, s, d)
			recordMacProof(t, s, agent, proof)
			locked := agent.ID
			if scenario == "cleared_competitor" {
				second := enrollMacAgent(t, r, registry.Scope{TenantID: 1, SiteID: 1})
				recordMacProof(t, s, second, proof)
				locked = second.ID
			}
			deadline := time.Now().Add(time.Second)
			if scenario == "challenge_expired" {
				if _, err := s.db.Exec(`UPDATE mdm_apple_mac_bindings SET expires_at=$2 WHERE id=$1`, proof.ChallengeID, deadline); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := s.db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			var pid int
			if err = tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(`SELECT id FROM uem_agent_identities WHERE id=$1 FOR UPDATE`, locked); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- s.ReconcileMacLinks(t.Context()) }()
			waitUntil := time.Now().Add(5 * time.Second)
			for {
				var waiting bool
				if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_locks WHERE NOT granted AND $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case err := <-done:
					t.Fatal("link did not wait for identity lock", err)
				default:
				}
				if time.Now().After(waitUntil) {
					t.Fatal("link never reached identity lock")
				}
				time.Sleep(time.Millisecond)
			}
			switch scenario {
			case "cleared_competitor":
				_, err = tx.Exec(`UPDATE uem_agent_hardware SET binding_challenge_id=NULL,binding_device_id=NULL,binding_token_hash=NULL WHERE device_id=$1`, locked)
			case "revoked":
				_, err = tx.Exec(`UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, locked)
			case "agent_expired":
				_, err = tx.Exec(`UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, locked)
			case "wrong_hash":
				_, err = tx.Exec(`UPDATE uem_agent_hardware SET binding_token_hash=repeat('0',64) WHERE device_id=$1`, locked)
			case "foreign_site":
				_, err = tx.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`)
			case "challenge_expired":
				if delay := time.Until(deadline) + 20*time.Millisecond; delay > 0 {
					time.Sleep(delay)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			var count int
			if err = s.db.QueryRow(`SELECT count(*) FROM uem_mac_devices`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 0
			if scenario == "cleared_competitor" {
				want = 1
			}
			if count != want {
				t.Fatal("stale pre-lock evidence decided association", count, want)
			}
		})
	}
}

func TestMacLinkReplicasCommitOneAssociation(t *testing.T) {
	s, d, r := macBindingFixture(t)
	agent := enrollMacAgent(t, r, registry.Scope{TenantID: 1, SiteID: 1})
	proof := deliverMacProof(t, s, d)
	recordMacProof(t, s, agent, proof)
	done := make(chan error, 4)
	for range 4 {
		go func() { done <- s.ReconcileMacLinks(t.Context()) }()
	}
	for range 4 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	var devices, audit, cleanup int
	if err := s.db.QueryRow(`SELECT (SELECT count(*) FROM uem_mac_devices),(SELECT count(*) FROM mdm_apple_audit WHERE action='apple.mac.channels.link'),(SELECT count(*) FROM mdm_apple_commands WHERE mac_binding AND request_type='RemoveProfile')`).Scan(&devices, &audit, &cleanup); err != nil || devices != 1 || audit != 1 || cleanup != 1 {
		t.Fatal("replicas duplicated association, audit or cleanup", devices, audit, cleanup, err)
	}
}
