package windows

import (
	"errors"
	"io"
	"mime"
	"net/http"
)

// PolicyHandler exposes the OnPremise XCEP operation against the durable store.
// It is not registered on the production gateway until WSTEP and provisioning
// are available. Its owner must configure TLS, bounded headers, request admission
// and read/write timeouts; forwarded headers cannot establish endpoint authority.
type PolicyHandler struct {
	store *Store
	url   string
	path  string
}

func NewPolicyHandler(store *Store, policyURL string) (*PolicyHandler, error) {
	if store == nil || store.db == nil || store.permissions == nil {
		return nil, ErrStore
	}
	if store.secrets == nil {
		return nil, ErrMasterKey
	}
	u, err := enrollmentEndpoint(policyURL)
	if err != nil {
		return nil, err
	}
	return &PolicyHandler{store: store, url: policyURL, path: u.Path}, nil
}

func (h *PolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.TLS == nil {
		writeEnrollmentHTTP(w, r, http.StatusBadRequest, "", nil)
		return
	}
	if r.URL == nil || r.URL.RawPath != "" || r.URL.Path != h.path || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || !sameEnrollmentEndpoint("https://"+r.Host+h.path, h.url) {
		writeEnrollmentHTTP(w, r, http.StatusNotFound, "", nil)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeEnrollmentHTTP(w, r, http.StatusMethodNotAllowed, "", nil)
		return
	}
	if !enrollmentContentType(r.Header, PolicyAction) {
		writeEnrollmentHTTP(w, r, http.StatusUnsupportedMediaType, "", nil)
		return
	}
	if r.ContentLength > MaxPolicyBytes {
		writeEnrollmentHTTP(w, r, http.StatusRequestEntityTooLarge, "", nil)
		return
	}
	if r.Body == nil {
		writePolicyFault(w, r, http.StatusBadRequest, "", "Sender", "MessageFormat")
		return
	}
	body := http.MaxBytesReader(w, r.Body, MaxPolicyBytes)
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		var sizeError *http.MaxBytesError
		if errors.As(err, &sizeError) {
			writeEnrollmentHTTP(w, r, http.StatusRequestEntityTooLarge, "", nil)
		} else {
			writePolicyFault(w, r, http.StatusBadRequest, "", "Sender", "MessageFormat")
		}
		return
	}
	request, err := ParsePolicyRequest(data, h.url)
	if err != nil {
		if errors.Is(err, ErrMustUnderstand) {
			writePolicyFault(w, r, http.StatusBadRequest, "", "MustUnderstand", "")
		} else {
			writePolicyFault(w, r, http.StatusBadRequest, "", "Sender", "MessageFormat")
		}
		return
	}
	response, err := h.store.EnrollmentPolicyResponse(r.Context(), request)
	if err != nil {
		if errors.Is(err, ErrCredential) {
			// Unknown, wrong, expired, consumed, revoked and out-of-scope
			// credentials all use the same MDE2 authentication fault.
			writePolicyFault(w, r, http.StatusInternalServerError, request.MessageID, "Receiver", "Authentication")
		} else {
			writePolicyFault(w, r, http.StatusInternalServerError, request.MessageID, "Receiver", "EnrollmentServer")
		}
		return
	}
	writeEnrollmentHTTP(w, r, http.StatusOK, mime.FormatMediaType("application/soap+xml", map[string]string{"charset": "utf-8", "action": PolicyResponseAction}), response)
}

func writePolicyFault(w http.ResponseWriter, r *http.Request, status int, relatesTo, code, subcode string) {
	writeEnrollmentFault(w, r, status, relatesTo, code, subcode, "The enrollment policy request could not be accepted.")
}
