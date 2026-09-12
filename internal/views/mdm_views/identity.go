package mdm_views

import (
	"context"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func IdentityRenewalState(ctx context.Context, r apple.IdentityRenewal) string {
	switch r.Status {
	case "queued":
		return mdmText(ctx, "mdm.identity.queued")
	case "issued":
		if r.TokenUpdatedAt != nil {
			return mdmText(ctx, "mdm.identity.push_updated")
		}
		return mdmText(ctx, "mdm.identity.issued")
	case "confirmed":
		return mdmText(ctx, "mdm.identity.confirmed")
	default:
		return StateLabel(ctx, r.Status)
	}
}

func IdentityRenewalHelp(ctx context.Context, code string) string {
	switch code {
	case "identity_expired":
		return mdmText(ctx, "mdm.identity.identity_expired")
	case "profile_inventory_required":
		return mdmText(ctx, "mdm.identity.profile_inventory_required")
	case "profile_metadata_invalid":
		return mdmText(ctx, "mdm.identity.profile_metadata_invalid")
	case "push_certificate_expired":
		return mdmText(ctx, "mdm.identity.push_certificate_expired")
	case "enrollment_settings_changed":
		return mdmText(ctx, "mdm.identity.enrollment_settings_changed")
	case "authority_unavailable":
		return mdmText(ctx, "mdm.identity.authority_unavailable")
	case "authority_expiring":
		return mdmText(ctx, "mdm.identity.authority_expiring")
	case "command_failed":
		return mdmText(ctx, "mdm.identity.command_failed")
	case "authorization_expired":
		return mdmText(ctx, "mdm.identity.authorization_expired")
	case "candidate_expired":
		return mdmText(ctx, "mdm.identity.candidate_expired")
	case "enrollment_inactive":
		return mdmText(ctx, "mdm.identity.enrollment_inactive")
	default:
		return mdmText(ctx, "mdm.identity.attention")
	}
}
