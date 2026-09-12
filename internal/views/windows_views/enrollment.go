package windows_views

import (
	"fmt"
	"net/url"
	"time"

	"github.com/open-uem/openuem-console/internal/mdm/windows"
)

type EnrollmentData struct {
	SetupError, PublicOrigin, Search string
	Authority                        *windows.EnrollmentAuthority
	Available                        bool
	Invitations                      []windows.EnrollmentInvitation
	Devices                          []windows.DeviceMetadata
	DeviceOffset, InvitationOffset   int
	MoreDevices, MoreInvitations     bool
	Created                          *windows.EnrollmentInvitation
	Credential                       *windows.UsernameCredential `json:"-" xml:"-" yaml:"-"`
}

func (EnrollmentData) String() string     { return "[protected Windows enrollment page]" }
func (v EnrollmentData) GoString() string { return v.String() }

func invitationStatus(i windows.EnrollmentInvitation) string {
	if i.RevokedAt != nil {
		return "Revoked"
	}
	if i.ConsumedAt != nil {
		return "Used"
	}
	if !i.ExpiresAt.After(time.Now()) {
		return "Expired"
	}
	return "Available"
}
func DeviceStatus(d windows.DeviceMetadata) string {
	if d.UnenrollmentReportedAt != nil && d.RevokedAt != nil {
		return "Disconnection reported; access revoked"
	}
	if d.RevokedAt != nil || d.CertificateRevokedAt != nil {
		return "Access revoked"
	}
	if !d.CertificateExpiresAt.After(time.Now()) {
		return "Certificate expired"
	}
	return "Certificate issued"
}
func pageURL(base string, d EnrollmentData, kind string, offset int) string {
	q := url.Values{"devices_offset": {fmt.Sprint(d.DeviceOffset)}, "invitations_offset": {fmt.Sprint(d.InvitationOffset)}}
	q.Set(kind, fmt.Sprint(offset))
	if d.Search != "" {
		q.Set("q", d.Search)
	}
	return base + "?" + q.Encode()
}
