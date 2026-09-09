package windows

import (
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// DiscoveryHandler is an immutable, read-only protocol handler. It is not
// registered on the production gateway until authenticated enrollment exists.
// Its owner must provide TLS, header/read/write timeouts and request admission
// limits. Forwarded headers are never a substitute for TLS or the configured URL.
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
		writeDiscoveryHTTP(w, r, http.StatusBadRequest, "", nil)
		return
	}
	if r.URL == nil || r.URL.RawPath != "" || r.URL.Path != DiscoveryPath || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || !sameEnrollmentEndpoint("https://"+r.Host+DiscoveryPath, h.url) {
		writeDiscoveryHTTP(w, r, http.StatusNotFound, "", nil)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		// Windows probes availability before sending the SOAP request. A probe
		// does not authenticate an account, allocate state or consume an invitation.
		writeDiscoveryHTTP(w, r, http.StatusOK, "text/html; charset=utf-8", nil)
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		writeDiscoveryHTTP(w, r, http.StatusMethodNotAllowed, "", nil)
		return
	}
	if !discoveryContentType(r.Header) {
		writeDiscoveryHTTP(w, r, http.StatusUnsupportedMediaType, "", nil)
		return
	}
	if r.ContentLength > MaxDiscoveryBytes {
		writeDiscoveryHTTP(w, r, http.StatusRequestEntityTooLarge, "", nil)
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
			writeDiscoveryHTTP(w, r, http.StatusRequestEntityTooLarge, "", nil)
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
	writeDiscoveryHTTP(w, r, http.StatusOK, mime.FormatMediaType("application/soap+xml", map[string]string{"charset": "utf-8", "action": DiscoveryResponseAction}), response)
}

func discoveryContentType(header http.Header) bool {
	if len(header.Values("Content-Type")) != 1 || len(header.Values("Content-Encoding")) > 1 || len(header.Values("Soapaction")) != 0 {
		return false
	}
	if encoding := header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return false
	}
	media, parameters, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || media != "application/soap+xml" {
		return false
	}
	for key, value := range parameters {
		switch key {
		case "charset":
			if !strings.EqualFold(value, "utf-8") {
				return false
			}
		case "action":
			if value != DiscoveryAction {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func writeDiscoveryHTTP(w http.ResponseWriter, r *http.Request, status int, contentType string, data []byte) {
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	// Windows enrollment responses must be sent as one message, not chunked.
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead && len(data) != 0 {
		_, _ = w.Write(data)
	}
}

type discoveryFault struct {
	XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Fault"`
	Code    struct {
		Value string `xml:"Value"`
	} `xml:"Code"`
	Reason struct {
		Text struct {
			Language string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
			Value    string `xml:",chardata"`
		} `xml:"Text"`
	} `xml:"Reason"`
}

func writeDiscoveryFault(w http.ResponseWriter, r *http.Request, status int, relatesTo, code string) {
	fault := discoveryFault{}
	fault.Code.Value = "s:" + code
	fault.Reason.Text.Language = "en"
	fault.Reason.Text.Value = "The enrollment discovery request could not be accepted."
	data, err := soapResponse(addressingNS+"/fault", relatesTo, fault)
	if err != nil {
		writeDiscoveryHTTP(w, r, http.StatusInternalServerError, "", nil)
		return
	}
	writeDiscoveryHTTP(w, r, status, "application/soap+xml; charset=utf-8", data)
}
