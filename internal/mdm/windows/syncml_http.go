package windows

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/open-uem/openuem-console/internal/security/access"
)

const syncMLContentType = "application/vnd.syncml.dm+xml"

// SyncMLHandler implements durable, authenticated XML sessions and the initial
// read-only DevInfo identity probe. It does not dispatch administrative CSP
// mutations and is not yet registered on the production gateway. Its owner must
// provide direct TLS with client certificates, admission limits and HTTP timeouts.
type SyncMLHandler struct {
	store   *Store
	options EnrollmentOptions
	path    string
}

func NewSyncMLHandler(store *Store, options EnrollmentOptions) (*SyncMLHandler, error) {
	if store == nil || store.db == nil {
		return nil, ErrStore
	}
	if store.secrets == nil {
		return nil, ErrMasterKey
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	u, _ := enrollmentEndpoint(options.ManagementURL)
	return &SyncMLHandler{store: store, options: options, path: u.Path}, nil
}

func (h *SyncMLHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.TLS == nil {
		writeEnrollmentHTTP(w, r, http.StatusBadRequest, "", nil)
		return
	}
	if r.URL == nil || r.URL.RawPath != "" || r.URL.Path != h.path || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || !sameEnrollmentEndpoint("https://"+r.Host+h.path, h.options.ManagementURL) {
		writeEnrollmentHTTP(w, r, http.StatusNotFound, "", nil)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeEnrollmentHTTP(w, r, http.StatusMethodNotAllowed, "", nil)
		return
	}
	certificate, err := managementPeerCertificate(r, h.options)
	if err != nil {
		writeEnrollmentHTTP(w, r, http.StatusForbidden, "", nil)
		return
	}
	if !syncMLHTTPContentType(r.Header) {
		writeEnrollmentHTTP(w, r, http.StatusUnsupportedMediaType, "", nil)
		return
	}
	if r.ContentLength > MaxSyncMLBytes {
		writeEnrollmentHTTP(w, r, http.StatusRequestEntityTooLarge, "", nil)
		return
	}
	if r.Body == nil {
		writeEnrollmentHTTP(w, r, http.StatusBadRequest, "", nil)
		return
	}
	body := http.MaxBytesReader(w, r.Body, MaxSyncMLBytes)
	defer body.Close()
	data, err := io.ReadAll(body)
	defer clear(data)
	if err != nil {
		status := http.StatusBadRequest
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			status = http.StatusRequestEntityTooLarge
		}
		writeEnrollmentHTTP(w, r, status, "", nil)
		return
	}
	response, err := h.store.processSyncML(r.Context(), certificate, data, h.options)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, ErrManagementIdentity), errors.Is(err, access.ErrDenied):
			status = http.StatusForbidden
		case errors.Is(err, ErrSyncML), errors.Is(err, ErrSyncMLSession), errors.Is(err, ErrSyncMLMessageSize), errors.Is(err, ErrCSPCommand):
			status = http.StatusBadRequest
		case errors.Is(err, ErrSyncMLReplay), errors.Is(err, ErrCSPAlreadySent):
			status = http.StatusConflict
		case errors.Is(err, ErrSyncMLSessionExpired), errors.Is(err, ErrCSPDeadline):
			status = http.StatusGone
		}
		// A fixed empty HTTP error cannot leak SQL details, credentials, device
		// hints or a partially committed protocol response.
		writeEnrollmentHTTP(w, r, status, "", nil)
		return
	}
	defer clear(response)
	writeEnrollmentHTTP(w, r, http.StatusOK, syncMLContentType+"; charset=utf-8", response)
}

func syncMLHTTPContentType(header http.Header) bool {
	if len(header.Values("Content-Type")) != 1 || len(header.Values("Content-Encoding")) != 0 {
		return false
	}
	media, parameters, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || media != syncMLContentType {
		return false
	}
	for key, value := range parameters {
		if key != "charset" || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}
