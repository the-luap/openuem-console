package inventory_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestDeviceListPaginationScopeAndAudit(t *testing.T) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	for i := range 55 {
		require.NoError(t, f.client.Agent.Create().SetID(fmt.Sprintf("page-%02d", i)).SetHostname("Same display name").SetOs("linux").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
	}
	read := func(filter inventory.DeviceFilter) *inventory.DevicePage {
		t.Helper()
		page, err := inventory.ReadDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, filter)
		require.NoError(t, err)
		return page
	}
	seen := map[string]bool{}
	filter := inventory.DeviceFilter{Platform: "linux", Search: "sAmE"}
	for {
		page := read(filter)
		require.LessOrEqual(t, len(page.Entries), 25)
		for _, d := range page.Entries {
			require.False(t, seen[d.ID], "duplicate identity between pages")
			seen[d.ID] = true
			require.Equal(t, f.scope.SiteID, d.SiteID)
		}
		if page.Next == "" {
			break
		}
		filter.After = page.Next
	}
	require.Len(t, seen, 55)
	for _, invalid := range []inventory.DeviceFilter{{After: "invalid"}, {Platform: "android"}, {Search: strings.Repeat("x", 257)}, {Search: "bad\nquery"}, {Platform: "windows", Search: filter.Search, After: filter.After}, {Platform: "linux", Search: "another", After: filter.After}} {
		page, err := inventory.ReadDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, invalid)
		require.ErrorIs(t, err, inventory.ErrReportFilter)
		require.Nil(t, page)
	}
	require.Empty(t, read(inventory.DeviceFilter{Search: "' OR true --"}).Entries)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetNickname("Literal %_ <device>").Exec(ctx))
	require.Len(t, read(inventory.DeviceFilter{Search: "%_"}).Entries, 1)
	for _, state := range []string{"ambiguous", "waiting", "orphan"} {
		update := f.client.Agent.UpdateOneID(f.id).ClearSite().SetAgentStatus(agent.AgentStatusEnabled)
		if state != "orphan" {
			update.AddSiteIDs(f.scope.SiteID)
		}
		if state == "ambiguous" {
			update.AddSiteIDs(f.otherSite)
		}
		if state == "waiting" {
			update.SetAgentStatus(agent.AgentStatusWaitingForAdmission)
		}
		require.NoError(t, update.Exec(ctx))
		require.Empty(t, read(inventory.DeviceFilter{Search: "%_"}).Entries)
		if state == "ambiguous" {
			page, err := inventory.ReadDevices(ctx, f.db, f.permissions, "admin", access.Scope{TenantID: f.scope.TenantID}, inventory.DeviceSources{}, inventory.DeviceFilter{Search: "%_"})
			require.NoError(t, err)
			require.Len(t, page.Entries, 1, "administrator cannot inspect an ambiguous assignment or sees duplicate identities")
		}
	}
	_, err := f.db.Exec(`ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_device_list_audit_failure CHECK(action<>'inventory.devices.list') NOT VALID`)
	require.NoError(t, err)
	page, err := inventory.ReadDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, inventory.DeviceFilter{})
	require.Error(t, err)
	require.Nil(t, page)
	_, err = f.db.Exec(`ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_device_list_audit_failure`)
	require.NoError(t, err)
	organization := access.Scope{TenantID: f.scope.TenantID}
	page, err = inventory.ReadDevices(ctx, f.db, f.permissions, "admin", organization, inventory.DeviceSources{}, inventory.DeviceFilter{})
	require.NoError(t, err)
	require.Len(t, page.Entries, 25)
	var count int
	require.NoError(t, f.db.QueryRow(`SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=$1 AND site_id=0 AND action='inventory.devices.list'`, organization.TenantID).Scan(&count))
	require.Equal(t, 2, count)
	page, err = inventory.ReadDevices(ctx, f.db, f.permissions, "viewer", organization, inventory.DeviceSources{}, inventory.DeviceFilter{})
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, page)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "viewer", 1, nil))
	page, err = inventory.ReadDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, filter)
	require.True(t, errors.Is(err, access.ErrDenied))
	require.Nil(t, page)
}

func TestDeviceListSearchesNativeWindowsBeyondFirstHundred(t *testing.T) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetLastContact(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)).Exec(ctx))
	store, err := windows.NewStoreWithMasterKey(f.db, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("w", 32))))
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	authority, err := store.InitializeAuthority(ctx, "admin", f.scope.TenantID, windows.AuthorityOptions{Organization: "Owned inventory fixture", MinimumKeyBits: 2048, ValiditySeconds: 86400, RenewalSeconds: 3600})
	require.NoError(t, err)
	for i := range 105 {
		invitation, _, err := store.CreateEnrollmentInvitation(ctx, "admin", f.scope, fmt.Sprintf("owned-%d@example.test", i), time.Hour)
		require.NoError(t, err)
		id, certificate := uuid.NewString(), uuid.NewString()
		name := fmt.Sprintf("Native device %03d", i)
		if i == 0 {
			name = "Oldest native device"
		}
		_, err = f.db.Exec(`INSERT INTO mdm_windows_devices(id,tenant_id,site_id,invitation_id,reported_device_id,device_name,enrollment_type,os_edition,os_version,application_version) VALUES($1::uuid,$2,$3,$4,$1::text,$5,'Device',4,'10.0.26100.1','10.0.26100.1')`, id, f.scope.TenantID, f.scope.SiteID, invitation.ID, name)
		require.NoError(t, err)
		_, err = f.db.Exec(`INSERT INTO mdm_windows_device_certificates(id,device_id,tenant_id,site_id,authority_id,certificate,fingerprint,public_key_fingerprint,serial,issued_at,expires_at) VALUES($1::uuid,$2::uuid,$3,$4,$5,'owned synthetic certificate',sha256($2::text::bytea),sha256($1::text::bytea),uuid_send($2::uuid),clock_timestamp(),clock_timestamp()+interval '1 day')`, certificate, id, f.scope.TenantID, f.scope.SiteID, authority.ID)
		require.NoError(t, err)
		_, err = f.db.Exec(`INSERT INTO mdm_windows_enrollments(invitation_id,tenant_id,site_id,device_id,certificate_id,request_digest,configuration_digest,encrypted_provisioning,encrypted_auth) VALUES($1,$2,$3,$4,$5,decode(repeat('01',32),'hex'),decode(repeat('02',32),'hex'),decode(repeat('03',30),'hex'),decode(repeat('04',30),'hex'))`, invitation.ID, f.scope.TenantID, f.scope.SiteID, id, certificate)
		require.NoError(t, err)
	}
	sources := inventory.DeviceSources{Windows: true}
	for _, search := range []string{"oldest", "26100"} {
		page, err := inventory.ReadDevices(ctx, f.db, f.permissions, "viewer", f.scope, sources, inventory.DeviceFilter{Platform: "windows", Search: search})
		require.NoError(t, err)
		if search == "oldest" {
			require.Len(t, page.Entries, 1)
			require.Equal(t, "Oldest native device", page.Entries[0].Name)
		} else {
			require.Len(t, page.Entries, 25)
			require.NotEmpty(t, page.Next)
		}
	}
	for _, order := range []string{"", "name_desc", "recent", "oldest"} {
		seen := map[string]bool{}
		filter := inventory.DeviceFilter{Platform: "windows", Sort: order}
		for {
			page, err := inventory.ReadDevices(ctx, f.db, f.permissions, "viewer", f.scope, sources, filter)
			require.NoError(t, err)
			if len(seen) == 0 && (order == "recent" || order == "oldest") {
				require.Equal(t, f.id, page.Entries[0].ID, "devices with missing contact time must follow reported contact times")
			}
			for _, d := range page.Entries {
				require.False(t, seen[d.ID])
				seen[d.ID] = true
			}
			if page.Next == "" {
				break
			}
			filter.After = page.Next
		}
		require.Len(t, seen, 106, "native identities and the separate desktop identity must all remain visible")
	}
	page, err := inventory.ReadDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, inventory.DeviceFilter{Search: "oldest"})
	require.NoError(t, err)
	require.Empty(t, page.Entries, "disabled source became visible")
}

func TestDeviceListSortOrdersAcrossContactTimeTies(t *testing.T) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	base := time.Date(2026, 9, 1, 12, 0, 0, 123456000, time.UTC)
	type entry struct {
		id, name string
		seen     time.Time
	}
	entries := []entry{}
	for i := range 55 {
		e := entry{id: fmt.Sprintf("sorted-%02d", i), name: fmt.Sprintf("Device %02d", 54-i), seen: base.Add(time.Duration(i/10) * time.Hour)}
		entries = append(entries, e)
		require.NoError(t, f.client.Agent.Create().SetID(e.id).SetHostname(e.name).SetOs("linux").SetLastContact(e.seen).SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
	}
	for _, order := range []string{"", "name_desc", "recent", "oldest"} {
		t.Run(order, func(t *testing.T) {
			expected := append([]entry(nil), entries...)
			sort.Slice(expected, func(i, j int) bool {
				a, b := expected[i], expected[j]
				if (order == "recent" || order == "oldest") && !a.seen.Equal(b.seen) {
					if order == "recent" {
						return a.seen.After(b.seen)
					}
					return a.seen.Before(b.seen)
				}
				if order == "name_desc" {
					return a.name > b.name
				}
				return a.name < b.name
			})
			filter := inventory.DeviceFilter{Platform: "linux", Sort: order}
			ids := []string{}
			for {
				page, err := inventory.ReadDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, filter)
				require.NoError(t, err)
				for _, d := range page.Entries {
					ids = append(ids, d.ID)
				}
				if page.Next == "" {
					break
				}
				filter.After = page.Next
			}
			want := make([]string, len(expected))
			for i, d := range expected {
				want[i] = d.id
			}
			require.Equal(t, want, ids)
			filter.Sort = "invalid"
			page, err := inventory.ReadDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, filter)
			require.ErrorIs(t, err, inventory.ErrReportFilter)
			require.Nil(t, page)
			filter.Sort = "recent"
			if order == "recent" {
				filter.Sort = ""
			}
			page, err = inventory.ReadDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, filter)
			require.ErrorIs(t, err, inventory.ErrReportFilter, "a cursor must not be reused with another order")
			require.Nil(t, page)
		})
	}
}

func TestDeviceListApplePlatformProjection(t *testing.T) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	store, err := apple.NewStore(f.db, strings.Repeat("k", 32))
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	_, err = f.db.Exec(`INSERT INTO mdm_apple_settings(tenant_id,public_url,organization,topic,push_expires_at,push_certificate,push_key,ca_certificate,ca_key) VALUES($1,'https://owned.example.test','Owned fixture','owned',clock_timestamp()+interval '1 day','owned','owned','owned','owned')`, f.scope.TenantID)
	require.NoError(t, err)
	for _, model := range []string{"iPhone15,2", "iPad13,4", "Mac14,2", "unidentified"} {
		_, err = f.db.Exec(`INSERT INTO mdm_apple_devices(id,tenant_id,site_id,name,model,serial_number,os_version,invite_expires_at,certificate_expires_at) VALUES($1,$2,$3,$4,$4,$4,'18.1',clock_timestamp()+interval '1 day',clock_timestamp()+interval '1 day')`, uuid.NewString(), f.scope.TenantID, f.scope.SiteID, model)
		require.NoError(t, err)
	}
	for _, platform := range []string{"ios", "ipados", "macos", "unknown", "apple"} {
		page, err := inventory.ReadDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{Apple: true}, inventory.DeviceFilter{Platform: platform})
		require.NoError(t, err)
		if platform == "apple" {
			require.Len(t, page.Entries, 4)
		} else {
			require.Len(t, page.Entries, 1)
			require.Equal(t, platform, page.Entries[0].Platform)
		}
	}
}
