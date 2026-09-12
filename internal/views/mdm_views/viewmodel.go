package mdm_views

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/views/locales"
)

type DeviceRow struct {
	ID, Name, Platform, OSVersion, Serial, Model, Status, URL string
	LastSeen                                                  *time.Time
}

type DevicePagination struct{ First, Next string }

type Detail struct {
	MacAdmin         *apple.MacAdminAccount
	MacAdminKeys     []apple.MacAdminKey
	ADE              *apple.ADEDeviceEnrollment
	ADEApplications  []apple.ADEApplication
	ADEPlatformSSO   *apple.ADEPlatformSSOStatus
	RecoveryLock     *apple.RecoveryLock
	RecoveryLockKeys []apple.RecoveryLockKey
	FileVault        *apple.FileVault
	FileVaultKeys    []apple.FileVaultKeyHistory
	Users            []apple.UserChannel
	AgentURL         string
	Mac              *apple.MacDevice
	MacBinding       *apple.MacBinding
	MacBindingReady  bool
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

type UserDetail struct {
	Device      *apple.Device
	User        *apple.UserChannel
	Commands    []apple.Command
	Assignments []apple.Assignment
	Profiles    []apple.Profile
}

func (d UserDetail) Path() string { return "/ios/" + d.Device.ID + "/users/" + d.User.ID }

func (d Detail) DevicePath() string {
	if d.Mac != nil {
		return "/mac/" + d.Mac.ID
	}
	return "/ios/" + d.Device.ID
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

func StateLabel(ctx context.Context, state string) string {
	switch state {
	case "consumed", "conflict", "stale", "blocked", "drifted", "agent",
		"pending", "authenticating", "enrolled", "unenrolled", "revoked",
		"queued", "sent", "acknowledged", "not_now", "deferred", "cancelled",
		"expired", "failed", "installed", "removed", "verifying", "verified",
		"missing", "not_managed", "unknown", "compliant", "update_required",
		"accepted", "invalid_token", "enforced", "unavailable", "waiting":
		return mdmText(ctx, "mdm.states."+state)
	default:
		return strings.ReplaceAll(Show(state), "_", " ")
	}
}

func mdmText(ctx context.Context, key string) string {
	if i18n.GetLocale(ctx) == nil {
		if english, err := locales.WithLocale(ctx, "en"); err == nil {
			ctx = english
		}
	}
	return i18n.T(ctx, key)
}
