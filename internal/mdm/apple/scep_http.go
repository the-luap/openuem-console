package apple

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"github.com/smallstep/scep"
)

// Do not advertise SCEPStandard: this enrollment service deliberately restricts
// messages to DER, RSA and SHA-2 and does not provide the optional query APIs.
const scepCapabilities = "AES\r\nPOSTPKIOperation\r\nSHA-256\r\nSHA-512\r\n"

func (s *Store) scepHTTP(w http.ResponseWriter, r *http.Request, deviceID string, limits *enrollmentLimiter, identity clientidentity.Policy) {
	s.handleSCEPHTTP(w, r, deviceID, "", limits, identity)
}

func (s *Store) handleSCEPHTTP(w http.ResponseWriter, r *http.Request, deviceID, renewalID string, limits *enrollmentLimiter, identity clientidentity.Policy) {
	if r.TLS == nil || !r.TLS.HandshakeComplete {
		http.Error(w, "HTTPS is required", 400)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", 405)
		return
	}
	if !limits.allow(r, identity) {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "too many enrollment requests", 429)
		return
	}
	if r.URL.RawPath != "" || len(r.URL.RawQuery) > 2*maxSCEPMessage {
		http.Error(w, "invalid SCEP request", 400)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query["operation"]) != 1 || len(query["message"]) > 1 || len(query) > 2 || (len(query) == 2 && query["message"] == nil) {
		http.Error(w, "invalid SCEP request", 400)
		return
	}
	operation := query.Get("operation")
	if operation != "GetCACaps" && operation != "GetCACert" && operation != "PKIOperation" {
		http.Error(w, "unsupported SCEP operation", 400)
		return
	}
	if (operation != "PKIOperation" && (r.Method != http.MethodGet || len(query.Get("message")) > 128)) || (r.Method == http.MethodPost && query["message"] != nil) {
		http.Error(w, "invalid SCEP request", 400)
		return
	}
	var data []byte
	if operation == "PKIOperation" {
		if r.Method == http.MethodPost {
			media, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if mediaErr != nil || media != "application/x-pki-message" || len(r.Header.Values("Content-Type")) != 1 {
				http.Error(w, "SCEP requires application/x-pki-message", 415)
				return
			}
			data, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxSCEPMessage))
			if err != nil {
				http.Error(w, "SCEP request exceeds 128 KiB", 413)
				return
			}
		} else {
			data, err = base64.StdEncoding.Strict().DecodeString(query.Get("message"))
		}
		if err != nil || len(data) == 0 || len(data) > maxSCEPMessage {
			http.Error(w, "invalid SCEP request", 400)
			return
		}
	}
	// Bound concurrent private-key operations as well as each caller's rate. The
	// limiter is separate from browser claims, with no attacker-controlled map keys.
	select {
	case limits.claims <- struct{}{}:
		defer func() { <-limits.claims }()
	default:
		w.Header().Set("Retry-After", "10")
		http.Error(w, "enrollment is busy", 429)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var a *scepAuthority
	if renewalID == "" {
		a, err = s.scepEnrollmentAuthority(ctx, deviceID, operation == "PKIOperation")
	} else {
		a, err = s.scepRenewalAuthority(ctx, deviceID, renewalID, operation == "PKIOperation")
	}
	if errors.Is(err, ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "SCEP is temporarily unavailable", 503)
		return
	}
	var response []byte
	contentType := "application/x-pki-message"
	switch operation {
	case "GetCACaps":
		contentType, response = "text/plain", []byte(scepCapabilities)
	case "GetCACert":
		contentType = "application/x-x509-ca-ra-cert"
		response, err = scep.DegenerateCertificates([]*x509.Certificate{a.ca, a.ra})
	case "PKIOperation":
		request, parseErr := parseSCEPRequest(data, a.ra, a.key, time.Now())
		if parseErr != nil {
			// Signature, ciphertext, padding, and CSR failures share one response.
			http.Error(w, "invalid SCEP request", 400)
			return
		}
		if renewalID == "" {
			response, err = s.scepEnroll(ctx, a, request)
		} else {
			response, err = s.scepRenew(ctx, a, request)
		}
	}
	if err != nil {
		http.Error(w, "SCEP is temporarily unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(response)
}
