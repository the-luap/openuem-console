// Package access defines persistent console permissions independently of login.
package access

import "errors"

type Role string

const (
	Administrator Role = "administrator"
	TenantAdmin   Role = "organization_admin"
	Operator      Role = "operator"
	Viewer        Role = "viewer"
)

type Capability string

const (
	ReadDevices          Capability = "devices.read"
	RefreshDevices       Capability = "devices.refresh"
	EnrollDevices        Capability = "devices.enroll"
	RevokeDevices        Capability = "devices.revoke"
	ReadProfiles         Capability = "profiles.read"
	ManageProfiles       Capability = "profiles.manage"
	AssignProfiles       Capability = "profiles.assign"
	ManageUpdates        Capability = "updates.manage"
	ManageCertificates   Capability = "certificates.manage"
	ReadAudit            Capability = "audit.read"
	ManageAuditRetention Capability = "audit.retention.manage"
	ManageAccess         Capability = "access.manage"
)

type Scope struct {
	TenantID int `json:"tenant_id"`
	SiteID   int `json:"site_id"`
}

type Grant struct {
	Role Role `json:"role"`
	Scope
}

type Principal struct {
	UserID   string  `json:"user_id"`
	Revision int     `json:"revision"`
	Grants   []Grant `json:"grants"`
}

func (g Grant) Validate() error {
	if g.TenantID < 0 || g.SiteID < 0 || (g.TenantID == 0 && g.SiteID != 0) {
		return errors.New("invalid permission scope")
	}
	switch g.Role {
	case Administrator:
		if g.TenantID != 0 || g.SiteID != 0 {
			return errors.New("server administrator must use the global scope")
		}
	case TenantAdmin:
		if g.TenantID <= 0 || g.SiteID != 0 {
			return errors.New("organization administrator must use one whole organization")
		}
	case Viewer, Operator:
		if g.TenantID <= 0 {
			return errors.New("viewer and operator require an organization")
		}
	default:
		return errors.New("unknown access role")
	}
	return nil
}

func (p Principal) IsAdministrator() bool {
	for _, g := range p.Grants {
		if g.Role == Administrator && g.TenantID == 0 && g.SiteID == 0 {
			return true
		}
	}
	return false
}

func roleAllows(role Role, capability Capability) bool {
	switch capability {
	case ReadDevices, ReadProfiles:
		return role == Viewer || role == Operator || role == TenantAdmin || role == Administrator
	case RefreshDevices, EnrollDevices, AssignProfiles, ManageUpdates:
		return role == Operator || role == TenantAdmin || role == Administrator
	case RevokeDevices, ManageProfiles, ManageCertificates, ReadAudit, ManageAuditRetention:
		return role == TenantAdmin || role == Administrator
	case ManageAccess:
		return role == Administrator
	default:
		return false
	}
}

// Can requires a grant covering the entire requested scope. A site grant never
// implies access to the whole organization, even if it is its only current site.
func (p Principal) Can(capability Capability, scope Scope) bool {
	if scope.TenantID < 0 || scope.SiteID < 0 || (scope.TenantID == 0 && scope.SiteID != 0) {
		return false
	}
	for _, g := range p.Grants {
		if g.Validate() != nil || !roleAllows(g.Role, capability) {
			continue
		}
		if g.Role == Administrator {
			return true
		}
		if g.TenantID == scope.TenantID && (g.SiteID == 0 || g.SiteID == scope.SiteID) {
			return true
		}
	}
	return false
}

func (p Principal) HasOrganization(tenant int) bool {
	if p.IsAdministrator() {
		return true
	}
	for _, g := range p.Grants {
		if g.TenantID == tenant && g.Validate() == nil {
			return true
		}
	}
	return false
}
