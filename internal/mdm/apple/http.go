package apple

import (
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"howett.net/plist"
)

// ProtocolHandler has no administrator endpoints or session cookies. Run it on
// the public MDM TLS listener; the authenticated console mounts its own UI/API.
func (s *Store) ProtocolHandler(logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		path := strings.TrimPrefix(r.URL.Path, "/mdm/apple/")
		if path == r.URL.Path {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(path, "enroll/") {
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				http.Error(w, "method not allowed", 405)
				return
			}
			data, err := s.EnrollmentProfile(r.Context(), strings.TrimPrefix(path, "enroll/"))
			if err != nil {
				protocolError(w, err, logger)
				return
			}
			w.Header().Set("Content-Type", "application/x-apple-aspen-config")
			w.Header().Set("Content-Disposition", `attachment; filename="OpenUEM.mobileconfig"`)
			_, _ = w.Write(data)
			return
		}
		if r.Method != http.MethodPut {
			w.Header().Set("Allow", "PUT")
			http.Error(w, "method not allowed", 405)
			return
		}
		parts := strings.Split(path, "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		if _, err := uuid.Parse(parts[0]); err != nil {
			http.NotFound(w, r)
			return
		}
		if parts[1] != "checkin" && parts[1] != "connect" {
			http.NotFound(w, r)
			return
		}
		// Never trust a client-supplied forwarded certificate header. TLS must
		// terminate here (a TCP/TLS passthrough proxy is also supported).
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "device certificate required", 401)
			return
		}
		d, err := s.AuthenticateCertificate(r.Context(), parts[0], r.TLS.PeerCertificates[0])
		if err != nil {
			protocolError(w, err, logger)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
		if err != nil {
			http.Error(w, "request exceeds 8 MiB", 413)
			return
		}
		var message map[string]any
		if _, err = plist.Unmarshal(body, &message); err != nil {
			http.Error(w, "invalid plist", 400)
			return
		}
		if parts[1] == "checkin" {
			if stringValue(message, "MessageType") == "DeclarativeManagement" {
				response, err := s.DeclarativeManagement(r.Context(), d, message)
				if err != nil {
					protocolError(w, err, logger)
					return
				}
				if response != nil {
					writeJSON(w, response)
				}
				return
			}
			if err = s.CheckIn(r.Context(), d, message); err != nil {
				protocolError(w, err, logger)
			}
			return
		}
		response, err := s.Connect(r.Context(), d, message)
		if err != nil {
			protocolError(w, err, logger)
			return
		}
		if len(response) > 0 {
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			_, _ = w.Write(response)
		}
	})
}

func protocolError(w http.ResponseWriter, err error, logger *slog.Logger) {
	switch {
	case errors.Is(err, ErrNotFound):
		http.Error(w, "not found", 404)
	case errors.Is(err, ErrUnauthorized):
		http.Error(w, "device identity rejected", 401)
	case errors.Is(err, ErrConflict):
		http.Error(w, "conflict", 409)
	default:
		// Detailed errors stay in server logs and are never exposed with SQL,
		// certificate material or enrollment tokens to a public caller.
		logger.Error("Apple MDM request failed", "error", err)
		http.Error(w, "unable to process MDM request", 500)
	}
}

func (s *Store) ProtocolServer(address string, logger *slog.Logger) *http.Server {
	return &http.Server{Addr: address, Handler: s.ProtocolHandler(logger), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 45 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10}
}
