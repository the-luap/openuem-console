package windows

import (
	"errors"
	"io"
	"mime"
	"net/http"
)

// DiscoveryHandler is an immutable, read-only protocol handler. ProtocolHandler
// provides production TLS, gateway trust, HTTP timeouts and request admission.
// Forwarded headers never change the configured endpoint URL.
type DiscoveryHandler struct {
	url     string
	options DiscoveryOptions
}

func NewDiscoveryHandler(discoveryURL string, options DiscoveryOptions) (*DiscoveryHandler, error) {
	u, err := enrollmentEndpoint(discoveryURL)
	if err != nil || u.Path != DiscoveryPath {
		return nil, ErrEndpoint
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	return &DiscoveryHandler{url: discoveryURL, options: options}, nil
}

func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.TLS == nil {
		writeEnrollmentHTTP(w, r, http.StatusBadRequest, "", nil)
		return
	}
	if r.URL == nil || r.URL.RawPath != "" || r.URL.Path != DiscoveryPath || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || !sameEnrollmentEndpoint("https://"+r.Host+DiscoveryPath, h.url) {
		writeEnrollmentHTTP(w, r, http.StatusNotFound, "", nil)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		// Windows probes availability before sending the SOAP request. A probe
		// does not authenticate an account, allocate state or consume an invitation.
		writeEnrollmentHTTP(w, r, http.StatusOK, "text/html; charset=utf-8", nil)
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		writeEnrollmentHTTP(w, r, http.StatusMethodNotAllowed, "", nil)
		return
	}
	if !enrollmentContentType(r.Header, DiscoveryAction) {
		writeEnrollmentHTTP(w, r, http.StatusUnsupportedMediaType, "", nil)
		return
	}
	if r.ContentLength > MaxDiscoveryBytes {
		writeEnrollmentHTTP(w, r, http.StatusRequestEntityTooLarge, "", nil)
		return
	}
	if r.Body == nil {
		writeDiscoveryFault(w, r, http.StatusBadRequest, "", "Sender")
		return
	}
	body := http.MaxBytesReader(w, r.Body, MaxDiscoveryBytes)
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		var sizeError *http.MaxBytesError
		if errors.As(err, &sizeError) {
			writeEnrollmentHTTP(w, r, http.StatusRequestEntityTooLarge, "", nil)
		} else {
			writeDiscoveryFault(w, r, http.StatusBadRequest, "", "Sender")
		}
		return
	}
	request, err := ParseDiscovery(data, h.url)
	if err != nil {
		code := "Sender"
		if errors.Is(err, ErrMustUnderstand) {
			code = "MustUnderstand"
		}
		writeDiscoveryFault(w, r, http.StatusBadRequest, "", code)
		return
	}
	response, err := BuildDiscoveryResponse(request, h.options)
	if err != nil {
		writeDiscoveryFault(w, r, http.StatusBadRequest, request.MessageID, "Sender")
		return
	}
	writeEnrollmentHTTP(w, r, http.StatusOK, mime.FormatMediaType("application/soap+xml", map[string]string{"charset": "utf-8", "action": DiscoveryResponseAction}), response)
}

func writeDiscoveryFault(w http.ResponseWriter, r *http.Request, status int, relatesTo, code string) {
	writeEnrollmentFault(w, r, status, relatesTo, code, "", "The enrollment discovery request could not be accepted.")
}
