package windows_views

import "github.com/open-uem/openuem-console/internal/mdm/windows"

func renewalState(phase string) string {
	switch phase {
	case "pending":
		return "Pending confirmation"
	case "confirmed":
		return "Replacement confirmed"
	case "canceled":
		return "Replacement canceled"
	default:
		return "Status unavailable"
	}
}

func canCancelRenewal(detail windows.CertificateRenewalDetail) bool {
	return detail.Renewal.Phase == "pending" && detail.Replacement.RevokedAt == nil
}
