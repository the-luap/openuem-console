package mdm_views

import (
	"fmt"
	"strings"
	"time"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

type DeviceRow struct {
	ID, Name, Platform, OSVersion, Serial, Model, Status, URL string
	LastSeen                                                  *time.Time
}

type Detail struct {
	Device           *apple.Device
	IdentityRenewals []apple.IdentityRenewal
	Commands         []apple.Command
	Assignments      []apple.Assignment
	Profiles         []apple.Profile
	Policy           *apple.UpdatePolicy
	Compliance       string
	Releases         []apple.OSRelease
	CatalogAt        *time.Time
}

func When(t *time.Time) string {
	if t == nil {
		return "Never reported"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}
func Number(n int) string { return fmt.Sprint(n) }
func Show(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func StateLabel(state string) string {
	labels := map[string]string{"agent": "Agent managed", "pending": "Pending", "authenticating": "Enrollment in progress", "enrolled": "Managed", "unenrolled": "Enrollment removed", "revoked": "Access revoked", "queued": "Queued", "sent": "Sent to device", "acknowledged": "Acknowledged", "not_now": "Deferred by device", "deferred": "Deferred by device", "cancelled": "Cancelled", "expired": "Expired", "failed": "Failed", "installed": "Installed", "removed": "Removed", "verifying": "Verifying on device", "verified": "Verified on device", "missing": "Expected profile not found", "not_managed": "Not managed", "unknown": "Waiting for fresh inventory", "compliant": "Up to date", "update_required": "Update required", "accepted": "Push accepted", "invalid_token": "Push token invalid", "enforced": "Update policy active", "unavailable": "Release no longer available"}
	if label, ok := labels[state]; ok {
		return label
	}
	return strings.ReplaceAll(Show(state), "_", " ")
}
