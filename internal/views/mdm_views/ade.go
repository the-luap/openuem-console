package mdm_views

import (
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"net/url"
	"time"
)

func adePageURL(server, after string) string {
	q := url.Values{"server": {server}}
	if after != "" {
		q.Set("after", after)
	}
	return "/ios/ade?" + q.Encode()
}
func adeSyncMessage(s apple.ADEServer) string {
	if s.Status == "pending" {
		return "Waiting for a verified Apple server token."
	}
	if s.Status == "disabled" {
		return "Synchronization is disabled. Import a current token for the same Apple server to reconnect."
	}
	if s.TokenExpiresAt == nil || !s.TokenExpiresAt.After(time.Now()) {
		return "The Apple server token has expired. Download and import a renewed token."
	}
	switch s.SyncError {
	case "throttled":
		return "Apple requested a later retry. Scheduled and manual synchronization respect this deadline."
	case "token_expired", "token_rejected":
		return "The token could not authenticate with Apple. Download and import a current token for this server."
	case "account_changed":
		return "Apple returned a different server or organization. Synchronization is paused until the original account binding is restored."
	case "cursor_reset":
		return "The previous synchronization could not be continued consistently. A new full fetch is scheduled; the last published assignments remain available."
	case "service_unavailable":
		return "Apple could not be reached or returned an invalid response. The last published assignments remain available; a retry is scheduled."
	}
	if s.SyncMode == "full" {
		return "A full fetch is scheduled or in progress. Assignments are published only after every page is received."
	}
	return "Incremental synchronization is scheduled hourly. Refresh this page to see the latest completed result."
}
