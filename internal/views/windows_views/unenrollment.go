package windows_views

import (
	"net/url"
	"time"

	"github.com/open-uem/openuem-console/internal/mdm/windows"
)

type UnenrollmentDraft struct {
	Form  url.Values `json:"-" xml:"-"`
	Error string     `json:"-" xml:"-"`
}

func (UnenrollmentDraft) String() string     { return "[protected Windows disconnection draft]" }
func (v UnenrollmentDraft) GoString() string { return v.String() }

func UnenrollmentRequestPending(detail windows.UnenrollmentRequestDetail) bool {
	return detail.Command.Phase == "queued" || detail.Command.Phase == "blocked" || detail.Command.DeliveredAt != nil && detail.Release == nil
}
func canRequestUnenrollment(device windows.DeviceMetadata) bool {
	return device.RevokedAt == nil && device.CertificateRevokedAt == nil && device.CertificateExpiresAt.After(time.Now())
}
func canCancelUnenrollment(detail windows.UnenrollmentRequestDetail) bool {
	return detail.Command.Phase == "queued" || detail.Command.Phase == "blocked"
}
func canReleaseUnenrollment(device windows.DeviceMetadata, detail windows.UnenrollmentRequestDetail) bool {
	return device.RevokedAt == nil && detail.Command.DeliveredAt != nil && detail.Release == nil && (detail.Command.Phase == "sent" || detail.Command.Phase == "unknown" || detail.Command.Phase == "acknowledged" || detail.Command.Phase == "failed")
}

func unenrollmentDeliveryReason(reason string) string {
	labels := map[string]string{
		"canceled": "Canceled before delivery.", "expired": "The delivery window expired before the request was sent.", "authority_lost": "The requesting administrator's permissions changed before delivery.",
		"session_aborted": "The delivery session was aborted; unresolved effects remain uncertain.", "session_expired": "The delivery session expired without a conclusive device outcome.", "session_failed": "The delivery session failed without a conclusive device outcome.", "session_completed": "The session ended without a conclusive device outcome.",
		"asynchronous_pending": "Windows accepted asynchronous processing; a final outcome has not been received.", "object_size": "The device's advertised object limit is too small for this request.", "message_size": "The device's advertised message limit is too small for this request.",
	}
	if label, ok := labels[reason]; ok {
		return label
	}
	return "Review command evidence for further delivery information."
}
