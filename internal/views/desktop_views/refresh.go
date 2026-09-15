package desktop_views

import "github.com/open-uem/openuem-console/internal/inventory"

type RefreshData struct {
	Request   *inventory.RefreshRequest
	NewID     string
	Available bool
}

func refreshState(request *inventory.RefreshRequest) string {
	if request == nil {
		return "No inventory refresh requested"
	}
	switch request.Status {
	case "accepted":
		return "Accepted for delivery"
	case "stopped":
		return "Stopped before delivery"
	case "unconfirmed":
		return "Delivery could not be confirmed"
	case "queued":
		if request.Attempts > 0 {
			return "Delivery not yet confirmed"
		}
		return "Waiting to send"
	default:
		return "Status unavailable"
	}
}
