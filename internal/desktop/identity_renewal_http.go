package desktop

import (
	"errors"
	"net/http"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/desktop/protocol"
)

// Renewal is authorized by the registry's independently loaded current identity
// and the complete signed proof. It consumes no invitation or installer release.
// In particular, candidate confirmation must remain reachable after the original
// certificate was retired and its commit reply was lost. A copied TLS/header leaf
// never substitutes for either required private-key proof.
func (h *PublicHandler) identityRenewal(w http.ResponseWriter, r *http.Request, route protocol.Route, body []byte) {
	var result any
	var err error
	switch route.Kind {
	case "renewal-prepare":
		request, decodeErr := enrollment.DecodeRenewalRequest(body)
		if decodeErr != nil || request.DeviceID != route.DeviceID || request.Origin != h.origin {
			http.Error(w, "invalid identity renewal request", http.StatusBadRequest)
			return
		}
		result, err = h.store.Registry.PrepareIdentityRenewal(r.Context(), *request)
	case "renewal-confirm":
		request, decodeErr := enrollment.DecodeRenewalConfirmation(body)
		if decodeErr != nil || request.DeviceID != route.DeviceID || request.Origin != h.origin {
			http.Error(w, "invalid identity renewal request", http.StatusBadRequest)
			return
		}
		result, err = h.store.Registry.ConfirmIdentityRenewal(r.Context(), *request)
	default:
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		code := ""
		switch {
		case errors.Is(err, registry.ErrRenewalNotDue):
			code = "not_due"
		case errors.Is(err, registry.ErrRenewalPending):
			code = "pending"
		case errors.Is(err, registry.ErrRenewalRecoveryPending):
			code = "recovery_pending"
		case errors.Is(err, registry.ErrDenied), errors.Is(err, registry.ErrNotFound):
			http.Error(w, "identity renewal is unavailable", http.StatusNotFound)
			return
		default:
			http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		publicJSONStatus(w, r, http.StatusConflict, enrollment.RenewalConflict{Version: enrollment.RenewalVersion, Code: code})
		return
	}
	publicJSON(w, r, result)
}
