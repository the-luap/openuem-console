package desktop_views

import (
	"net/url"
	"strings"
	"time"

	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/desktop"
)

type EnrollmentData struct {
	SetupError, PublicOrigin, Organization string
	Authority                              *registry.Authority
	Invitations                            desktop.Page[desktop.InvitationRow]
	Identities                             desktop.Page[desktop.IdentityRow]
	InvitationSetup, FormError             string
	ReleaseDigest, ReleaseVersion          string
	ReleaseExpires                         time.Time
	Targets                                []artifacts.Artifact
	InvitationForm                         InvitationForm
	Created                                *desktop.InstallerInvitation
}

type InvitationForm struct {
	Target         string
	MaxUses, Hours int
}

func targetLabel(platform, architecture string) string {
	if platform == "macos" {
		if architecture == "arm64" {
			return "Mac — Apple silicon"
		}
		return "Mac — Intel"
	}
	if architecture == "arm64" {
		return "Windows — ARM64"
	}
	return "Windows — x64"
}

func invitationToken(invitation *desktop.InstallerInvitation) string {
	if invitation == nil {
		return ""
	}
	_, token, _ := strings.Cut(invitation.URL, "/enroll/desktop/")
	return token
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
