package windows

import (
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

// WSTEPHandler implements initial OnPremise issuance and certificate-authenticated
// renewal with bounded exact retries. Account/federated renewal is separate.
// ProtocolHandler supplies production TLS, gateway trust, admission limits and
// header/read/write timeouts. Enrollment console configuration is separate.
type WSTEPHandler struct {
	store    *Store
	url      string
	path     string
	options  EnrollmentOptions
	identity clientidentity.Policy
}

func NewWSTEPHandler(store *Store, enrollmentURL string, options EnrollmentOptions) (*WSTEPHandler, error) {
	return newWSTEPHandlerWithIdentity(store, enrollmentURL, options, clientidentity.Policy{})
}

func newWSTEPHandlerWithIdentity(store *Store, enrollmentURL string, options EnrollmentOptions, identity clientidentity.Policy) (*WSTEPHandler, error) {
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
	return &WSTEPHandler{store: store, url: enrollmentURL, path: u.Path, options: options, identity: identity}, nil
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
	defer clear(data)
	if err != nil {
		var sizeError *http.MaxBytesError
		if errors.As(err, &sizeError) {
			writeEnrollmentHTTP(w, r, http.StatusRequestEntityTooLarge, "", nil)
		} else {
			writeWSTEPFault(w, r, http.StatusBadRequest, "", "Sender", "MessageFormat")
		}
		return
	}
	message, err := parseWSTEPMessage(data, h.url)
	if err != nil {
		if errors.Is(err, ErrMustUnderstand) {
			writeWSTEPFault(w, r, http.StatusBadRequest, "", "MustUnderstand", "")
		} else {
			writeWSTEPFault(w, r, http.StatusBadRequest, "", "Sender", "MessageFormat")
		}
		return
	}
	requestType, err := wstepRequestType(message)
	if err != nil {
		writeWSTEPFault(w, r, http.StatusBadRequest, "", "Sender", "MessageFormat")
		return
	}
	if requestType == trustNS+"/Renew" {
		h.serveRenewal(w, r, message)
		return
	}
	request, err := parseWSTEPInitial(message)
	if err != nil {
		writeWSTEPFault(w, r, http.StatusBadRequest, "", "Sender", "MessageFormat")
		return
	}
	response, err := h.store.EnrollWindows(r.Context(), request, h.options)
	if err != nil {
		writeWSTEPServiceError(w, r, request.MessageID, err)
		return
	}
	writeEnrollmentHTTP(w, r, http.StatusOK, mime.FormatMediaType("application/soap+xml", map[string]string{"charset": "utf-8", "action": WSTEPResponseAction}), response)
}

func (h *WSTEPHandler) serveRenewal(w http.ResponseWriter, r *http.Request, message *soapMessage) {
	// Renewal cannot enter initial issuance, even if its token or credentials
	// are malformed. The actual TLS/RFC 9440 leaf is checked at this endpoint.
	certificate, err := windowsPeerCertificate(r, h.url, h.identity)
	if err != nil {
		writeWSTEPServiceError(w, r, message.MessageID, err)
		return
	}
	request, err := parseWSTEPRenewal(message)
	if err != nil {
		writeWSTEPFault(w, r, http.StatusBadRequest, "", "Sender", "MessageFormat")
		return
	}
	response, err := h.store.RenewWindowsCertificate(r.Context(), certificate, *request, h.options)
	if err != nil {
		writeWSTEPServiceError(w, r, request.MessageID, err)
		return
	}
	writeEnrollmentHTTP(w, r, http.StatusOK, mime.FormatMediaType("application/soap+xml", map[string]string{"charset": "utf-8", "action": WSTEPResponseAction}), response)
}

func writeWSTEPServiceError(w http.ResponseWriter, r *http.Request, messageID string, err error) {
	subcode := "EnrollmentServer"
	switch {
	case errors.Is(err, ErrCredential), errors.Is(err, ErrEnrollmentReplay), errors.Is(err, ErrManagementIdentity):
		subcode = "Authentication"
	case errors.Is(err, ErrCSR), errors.Is(err, ErrRenewalProof), errors.Is(err, ErrCertificateRenewal):
		subcode = "CertificateRequest"
	case errors.Is(err, ErrWindowsDeviceType), errors.Is(err, ErrRenewalWindow), errors.Is(err, ErrRenewalConflict):
		subcode = "Authorization"
	}
	writeWSTEPFault(w, r, http.StatusInternalServerError, messageID, "Receiver", subcode)
}

func writeWSTEPFault(w http.ResponseWriter, r *http.Request, status int, relatesTo, code, subcode string) {
	writeEnrollmentFault(w, r, status, relatesTo, code, subcode, "The certificate enrollment request could not be accepted.")
}
