package desktop_views

import (
	"net/url"
	"time"

	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/desktop"
)

type EnrollmentData struct {
	SetupError, PublicOrigin, Organization string
	Authority                              *registry.Authority
	Invitations                            desktop.Page[desktop.InvitationRow]
	Identities                             desktop.Page[desktop.IdentityRow]
}

func invitationState(row desktop.InvitationRow) string {
	if row.RevokedAt != nil {
		return "Revoked"
	}
	if !row.ExpiresAt.After(time.Now()) {
		return "Expired"
	}
	if row.Uses >= row.MaxUses {
		return "Used"
	}
	return "Available"
}

func identityState(row desktop.IdentityRow) string {
	if row.RevokedAt != nil {
		return "Revoked"
	}
	if !row.CertificateExpiresAt.After(time.Now()) {
		return "Expired"
	}
	if !row.ScopeValid {
		return "Site assignment changed"
	}
	if !row.ConsumerReady {
		return "Preparing command channel"
	}
	return "Identity ready"
}

func nextPage(base, key, cursor string) string {
	values := url.Values{key: {cursor}}
	return base + "?" + values.Encode()
}
