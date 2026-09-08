package webserver

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/controllers/router"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/controllers/webserver/handlers"
	"github.com/open-uem/openuem-console/internal/desktop"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

type WebServer struct {
	Router         *echo.Echo
	Handler        *handlers.Handler
	Server         *http.Server
	SessionManager *sessions.SessionManager
	AppleServer    *http.Server
	AppleCancel    context.CancelFunc
	DesktopServer  *http.Server
	desktopPublic  *desktop.PublicHandler
	reminderMu     sync.Mutex
	reminderCancel context.CancelFunc
	reminderDone   chan struct{}
	auditMu        sync.Mutex
	auditCancel    context.CancelFunc
	auditDone      chan struct{}
}

func New(m *models.Model, natsServers string, s *sessions.SessionManager, ts gocron.Scheduler, jwtKey, certPath, keyPath, sftpKeyPath, caCertPath, server, consolePort, authPort, tmpDownloadDir, domain, orgName, orgProvince, orgLocality, orgAddress, country, reverseProxyAuthPort, reverseProxyServer, serverReleasesFolder, commonFolder, version, encryptionMasterKey string, reEnableCertAuth, reEnablePasswdAuth, reOpenUEMUser bool, authLogger *log.Logger) *WebServer {
	var err error
	w := WebServer{}

	// Get max upload size setting
	maxUploadSize, err := m.GetMaxUploadSize()
	if err != nil {
		maxUploadSize = "512M"
		log.Println("[ERROR]: could not get max upload size from database")
	}

	// Get register rate limit setting
	registerRateLimit, err := m.GetRegisterRateLimit()
	if err != nil {
		registerRateLimit = 3
		log.Println("[ERROR]: could not get register rate limit from database")
	}

	// Router
	w.Router = router.New(s, server, consolePort, maxUploadSize)

	// Create Handler and register its router
	w.Handler = handlers.NewHandler(m, natsServers, s, ts, jwtKey, certPath, keyPath, sftpKeyPath, caCertPath, server, consolePort, authPort, tmpDownloadDir, domain, orgName, orgProvince, orgLocality, orgAddress, country, reverseProxyAuthPort, reverseProxyServer, serverReleasesFolder, commonFolder, version, encryptionMasterKey, reEnableCertAuth, reEnablePasswdAuth, authLogger)
	w.Handler.Register(w.Router, registerRateLimit)
	w.initApple(encryptionMasterKey)
	w.initDesktop(encryptionMasterKey)
	w.initMacLinks()

	// Add the session manager
	w.SessionManager = s

	return &w
}

func (w *WebServer) Serve(address, certFile, certKey string) error {
	permissions, err := access.NewStore(w.Handler.Model.DB)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = permissions.Migrate(ctx); err != nil {
		return err
	}
	initialAdmin := os.Getenv("OPENUEM_BOOTSTRAP_ADMIN")
	if initialAdmin == "" {
		initialAdmin = "openuem"
	}
	if err = permissions.Bootstrap(ctx, initialAdmin); err != nil {
		return err
	}
	w.Handler.Access = permissions
	w.Handler.Audit, err = audit.NewStore(w.Handler.Model.DB, permissions)
	if err != nil {
		return err
	}
	if err = w.Handler.Audit.Migrate(ctx); err != nil {
		return err
	}
	w.startAuditRetention()
	defer w.stopAuditRetention()
	w.startAppleReminders()
	defer w.stopAppleReminders()
	identity, err := clientidentity.FromEnvironment()
	if err != nil {
		return err
	}
	if err := w.startDesktop(certFile, certKey); err != nil {
		return err
	}
	defer w.stopDesktop()
	if err := w.startApple(certFile, certKey); err != nil {
		return err
	}
	w.Server = &http.Server{
		Addr:      address,
		Handler:   identity.Protect(w.Router),
		TLSConfig: &tls.Config{},
	}

	identity.ConfigureTLS(w.Server.TLSConfig)
	return w.Server.ListenAndServeTLS(certFile, certKey)
}

func (w *WebServer) Close() error {
	w.stopAuditRetention()
	w.stopAppleReminders()
	w.stopDesktop()
	if w.AppleCancel != nil {
		w.AppleCancel()
	}
	if w.AppleServer != nil {
		_ = w.AppleServer.Close()
	}
	if w.Server == nil {
		return nil
	}
	return w.Server.Close()
}
