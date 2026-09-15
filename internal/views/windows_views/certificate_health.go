package windows_views

import (
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/open-uem/openuem-console/internal/mdm/windows"
)

var certificateHealthFilters = []struct{ Value, Label string }{
	{"attention", "Needs attention"}, {"all", "All devices"}, {"renewal_due", "Renewal window open"}, {"expires_soon", "Expires within warning period"}, {"expired", "Certificate expired"}, {"pending", "Replacement pending"}, {"retired", "Device access revoked"},
}

func certificateHealthLabel(state string) string {
	switch state {
	case "valid":
		return "Certificate valid"
	case "renewal_due":
		return "Renewal window open"
	case "expires_soon":
		return "Certificate expires soon"
	case "expired":
		return "Certificate expired"
	case "not_yet_valid":
		return "Not yet valid"
	case "revoked":
		return "Certificate revoked"
	case "retired":
		return "Device access revoked"
	case "available":
		return "Issuance available"
	case "issuance_ending":
		return "Issuance window ends soon"
	case "issuance_unavailable":
		return "Issuance unavailable"
	default:
		return "Status unavailable"
	}
}

func certificateHealthPage(base string, o windows.CertificateHealthOptions, offset int) string {
	return base + "?" + url.Values{"q": {o.Search}, "filter": {o.Filter}, "days": {strconv.Itoa(o.WithinDays)}, "offset": {strconv.Itoa(offset)}}.Encode()
}

func certificateHealthDeviceURL(d windows.DeviceMetadata, suffix string) string {
	return fmt.Sprintf("/tenant/%d/site/%d/windows/%s%s", d.TenantID, d.SiteID, d.ID, suffix)
}

func certificateHealthDuration(seconds int64) string {
	if seconds%86400 == 0 {
		return fmt.Sprintf("%d days", seconds/86400)
	}
	return (time.Duration(seconds) * time.Second).String()
}
