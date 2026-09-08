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
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"howett.net/plist"
)

// ProtocolHandler has no administrator endpoints. Its enrollment browser cookie
// cannot authenticate device protocol or console requests.
func (s *Store) ProtocolHandler(logger *slog.Logger) http.Handler {
	return s.ProtocolHandlerWithIdentity(logger, clientidentity.Policy{})
}

func (s *Store) ProtocolHandlerWithIdentity(logger *slog.Logger, identity clientidentity.Policy) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	portalLimits := newEnrollmentLimiter()
	scepLimits := newEnrollmentLimiter()
	return identity.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin")
		path := strings.TrimPrefix(r.URL.Path, "/mdm/apple/")
		if path == r.URL.Path {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(path, "enroll/") {
			s.enrollmentPage(w, r, strings.TrimPrefix(path, "enroll/"), portalLimits, identity)
			return
		}
		scepParts := strings.Split(path, "/")
		if (len(scepParts) == 2 || len(scepParts) == 3) && scepParts[1] == "scep" {
			id, err := uuid.Parse(scepParts[0])
			if err != nil || id.String() != scepParts[0] {
				http.NotFound(w, r)
				return
			}
			renewalID := ""
			if len(scepParts) == 3 {
				renewal, err := uuid.Parse(scepParts[2])
				if err != nil || renewal.String() != scepParts[2] {
					http.NotFound(w, r)
					return
				}
				renewalID = scepParts[2]
			}
			s.handleSCEPHTTP(w, r, scepParts[0], renewalID, scepLimits, identity)
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
		cert, err := identity.Certificate(r)
		if err != nil {
			http.Error(w, "device certificate required", 401)
			return
		}
		d, err := s.AuthenticateCertificate(r.Context(), parts[0], cert)
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
		message = normalizeDeviceMarker(d, message)
		if userChannelMessage(message) {
			var response []byte
			if parts[1] == "checkin" {
				response, err = s.UserCheckIn(r.Context(), d, message)
			} else {
				response, err = s.UserConnect(r.Context(), d, message)
			}
			if err != nil {
				protocolError(w, err, logger)
				return
			}
			if len(response) > 0 {
				w.Header().Set("Content-Type", "application/xml; charset=utf-8")
				_, _ = w.Write(response)
			}
			return
		}
		if parts[1] == "checkin" {
			if kind := stringValue(message, "MessageType"); kind == "SetBootstrapToken" || kind == "GetBootstrapToken" {
				response, err := s.BootstrapToken(r.Context(), d, message)
				if err != nil {
					protocolError(w, err, logger)
					return
				}
				if kind == "GetBootstrapToken" {
					data, err := plist.Marshal(response, plist.XMLFormat)
					if err != nil {
						protocolError(w, err, logger)
						return
					}
					w.Header().Set("Content-Type", "application/xml; charset=utf-8")
					_, _ = w.Write(data)
				}
				return
			}
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
		defer clear(response)
		if err != nil {
			protocolError(w, err, logger)
			return
		}
		if len(response) > 0 {
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			_, _ = w.Write(response)
		}
	}))
}

func protocolError(w http.ResponseWriter, err error, logger *slog.Logger) {
	switch {
	case errors.Is(err, ErrUserChannelDeclined):
		http.Error(w, "user-channel management is unavailable for this enrollment", http.StatusGone)
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
	return s.ProtocolServerWithIdentity(address, logger, clientidentity.Policy{})
}

func (s *Store) ProtocolServerWithIdentity(address string, logger *slog.Logger, identity clientidentity.Policy) *http.Server {
	config := &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}
	identity.ConfigureTLS(config)
	return &http.Server{Addr: address, Handler: s.ProtocolHandlerWithIdentity(logger, identity), TLSConfig: config, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 45 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10}
}
