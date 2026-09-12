package windows

import (
	"encoding/xml"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

func enrollmentContentType(header http.Header, action string) bool {
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
			if value != action {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func writeEnrollmentHTTP(w http.ResponseWriter, r *http.Request, status int, contentType string, data []byte) {
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

type enrollmentFault struct {
	XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Fault"`
	Code    struct {
		Value   string                  `xml:"Value"`
		Subcode *enrollmentFaultSubcode `xml:"Subcode,omitempty"`
	} `xml:"Code"`
	Reason struct {
		Text struct {
			Language string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
			Value    string `xml:",chardata"`
		} `xml:"Text"`
	} `xml:"Reason"`
}

type enrollmentFaultSubcode struct {
	Value string `xml:"Value"`
}

func writeEnrollmentFault(w http.ResponseWriter, r *http.Request, status int, relatesTo, code, subcode, reason string) {
	fault := enrollmentFault{}
	fault.Code.Value = "s:" + code
	if subcode != "" {
		fault.Code.Subcode = &enrollmentFaultSubcode{Value: "s:" + subcode}
	}
	fault.Reason.Text.Language = "en"
	fault.Reason.Text.Value = reason
	data, err := soapResponse(addressingNS+"/fault", relatesTo, fault)
	if err != nil {
		writeEnrollmentHTTP(w, r, http.StatusInternalServerError, "", nil)
		return
	}
	writeEnrollmentHTTP(w, r, status, "application/soap+xml; charset=utf-8", data)
}
