package windows_views

import "fmt"

func certificateReminderKind(kind string) string {
	switch kind {
	case "device_expiry":
		return "Device certificate expiry"
	case "issuer_expiry":
		return "CA certificate expiry"
	case "issuer_issuance":
		return "Full-lifetime issuance deadline"
	default:
		return "Certificate deadline"
	}
}
func certificateReminderStage(stage int) string {
	if stage == 0 {
		return "Deadline reached"
	}
	if stage == 1 {
		return "Within 1 day"
	}
	return fmt.Sprintf("Within %d days", stage)
}

func certificateReminderSMTPStatus(count int) string {
	if count == 1 {
		return "1 pending delivery needs valid SMTP settings."
	}
	return fmt.Sprintf("%d pending deliveries need valid SMTP settings.", count)
}
