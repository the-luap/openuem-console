package windows

import (
	"errors"
	"io"
	"mime"
	"net/http"
)

// WSTEPHandler implements initial OnPremise issuance and bounded exact retries.
// It is not registered on the production gateway while the SyncML management
// service and console enrollment configuration are still being implemented.
// The owner must provide TLS, admission limits and header/read/write timeouts.
type WSTEPHandler struct {
	store   *Store
	url     string
	path    string
	options EnrollmentOptions
}

func NewWSTEPHandler(store *Store, enrollmentURL string, options EnrollmentOptions) (*WSTEPHandler, error) {
	if store == nil || store.db == nil || store.permissions == nil {
		return nil, ErrStore
	}
	if store.secrets == nil {
		return nil, ErrMasterKey
	}
	u, err := enrollmentEndpoint(enrollmentURL)
	if err != nil {
		return nil, err
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	return &WSTEPHandler{store: store, url: enrollmentURL, path: u.Path, options: options}, nil
}

func (h *WSTEPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	if !enrollmentContentType(r.Header, WSTEPAction) {
		writeEnrollmentHTTP(w, r, http.StatusUnsupportedMediaType, "", nil)
		return
	}
	if r.ContentLength > MaxWSTEPBytes {
		writeEnrollmentHTTP(w, r, http.StatusRequestEntityTooLarge, "", nil)
		return
	}
	if r.Body == nil {
		writeWSTEPFault(w, r, http.StatusBadRequest, "", "Sender", "MessageFormat")
		return
	}
	body := http.MaxBytesReader(w, r.Body, MaxWSTEPBytes)
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		var sizeError *http.MaxBytesError
		if errors.As(err, &sizeError) {
			writeEnrollmentHTTP(w, r, http.StatusRequestEntityTooLarge, "", nil)
		} else {
			writeWSTEPFault(w, r, http.StatusBadRequest, "", "Sender", "MessageFormat")
		}
		return
	}
	request, err := ParseWSTEPRequest(data, h.url)
	if err != nil {
		if errors.Is(err, ErrMustUnderstand) {
			writeWSTEPFault(w, r, http.StatusBadRequest, "", "MustUnderstand", "")
		} else {
			writeWSTEPFault(w, r, http.StatusBadRequest, "", "Sender", "MessageFormat")
		}
		return
	}
	response, err := h.store.EnrollWindows(r.Context(), request, h.options)
	if err != nil {
		subcode := "EnrollmentServer"
		switch {
		case errors.Is(err, ErrCredential), errors.Is(err, ErrEnrollmentReplay):
			subcode = "Authentication"
		case errors.Is(err, ErrCSR):
			subcode = "CertificateRequest"
		case errors.Is(err, ErrWindowsDeviceType):
			subcode = "Authorization"
		}
		writeWSTEPFault(w, r, http.StatusInternalServerError, request.MessageID, "Receiver", subcode)
		return
	}
	writeEnrollmentHTTP(w, r, http.StatusOK, mime.FormatMediaType("application/soap+xml", map[string]string{"charset": "utf-8", "action": WSTEPResponseAction}), response)
}

func writeWSTEPFault(w http.ResponseWriter, r *http.Request, status int, relatesTo, code, subcode string) {
	writeEnrollmentFault(w, r, status, relatesTo, code, subcode, "The certificate enrollment request could not be accepted.")
}
