package access

import "testing"

func TestRolesEnforceScopeAndCapabilities(t *testing.T) {
	scopes := []Scope{{TenantID: 1}, {TenantID: 1, SiteID: 11}, {TenantID: 1, SiteID: 12}, {TenantID: 2, SiteID: 21}, {}}
	for _, role := range []Role{Viewer, Operator, TenantAdmin, Administrator} {
		grant := Grant{Role: role, Scope: Scope{TenantID: 1, SiteID: 11}}
		if role == TenantAdmin {
			grant.SiteID = 0
		}
		if role == Administrator {
			grant.Scope = Scope{}
		}
		p := Principal{UserID: "user", Grants: []Grant{grant}}
		for _, scope := range scopes {
			scopeAllowed := role == Administrator || scope.TenantID == 1 && (role == TenantAdmin || scope.SiteID == 11)
			for _, capability := range []Capability{ReadDevices, ReadProfiles, ReadSoftware, ManageSoftware, AssignSoftware, EnrollDevices, RefreshDevices, AssignProfiles, ManageUpdates, ManageProfiles, ManageCertificates, RevokeDevices, ManageAccess, ReadAudit, ManageAuditRetention, ManageDeviceSecurity, RetrieveRecoveryKeys} {
				want := scopeAllowed
				switch capability {
				case ManageAccess:
					want = role == Administrator
				case ManageSoftware, ManageProfiles, ManageCertificates, RevokeDevices, ReadAudit, ManageAuditRetention, ManageDeviceSecurity, RetrieveRecoveryKeys:
					want = scopeAllowed && (role == TenantAdmin || role == Administrator)
				case EnrollDevices, RefreshDevices, AssignProfiles, ManageUpdates, AssignSoftware:
					want = scopeAllowed && role != Viewer
				}
				if got := p.Can(capability, scope); got != want {
					t.Errorf("%s %s %+v: got %v want %v", role, capability, scope, got, want)
				}
			}
		}
		if p.Can(Capability("new.unknown"), Scope{TenantID: 1, SiteID: 11}) {
			t.Fatal("new capability implicitly authorized")
		}
	}
	for _, grant := range []Grant{{Role: Administrator, Scope: Scope{TenantID: 1}}, {Role: Viewer}, {Role: TenantAdmin, Scope: Scope{TenantID: 1, SiteID: 11}}, {Role: "invented", Scope: Scope{TenantID: 1}}} {
		if grant.Validate() == nil {
			t.Error("invalid grant accepted", grant)
		}
	}
}

func TestSiteGrantCannotAuthorizeAnOrganizationWideAction(t *testing.T) {
	p := Principal{Grants: []Grant{{Role: Operator, Scope: Scope{TenantID: 1, SiteID: 11}}, {Role: Operator, Scope: Scope{TenantID: 1, SiteID: 12}}}}
	if p.Can(AssignProfiles, Scope{TenantID: 1}) {
		t.Fatal("multiple site grants became organization-wide authority")
	}
	if p.HasOrganization(2) || !p.HasOrganization(1) {
		t.Fatal("organization visibility is incorrect")
	}
}
