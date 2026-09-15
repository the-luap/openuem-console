package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nats-io/nats.go"
	openuem "github.com/open-uem/nats"
)

func TestIndividualConsoleRejectsLegacyFallback(t *testing.T) {
	h := &Handler{IndividualAgentService: &openuem.ServiceConnection{Servers: "tls://127.0.0.1:1", KeyFile: "/missing-console.seed", CAFile: "/missing-ca.pem"}}
	if err := h.StartNATSConnectJob(); err == nil {
		t.Fatal("missing individual key accepted")
	}
	if h.NATSConnection != nil || h.JetStream != nil || h.NATSConnectJob != nil || h.AgentStream != nil || h.ServerStream != nil {
		t.Fatal("failed individual connection created legacy state")
	}
}

func TestIndividualConsoleDisablesEndpointInbound(t *testing.T) {
	h := &Handler{IndividualAgentService: &openuem.ServiceConnection{}}
	for _, handler := range []echo.HandlerFunc{
		h.BrowseLogicalDisk, h.NewFolder, h.DeleteItem, h.RenameItem, h.DeleteMany,
		h.UploadFile, h.DownloadFile, h.DownloadFolderAsZIP, h.DownloadManyAsZIP,
		h.RemoteAssistance, h.ComputerStartVNC, h.ComputerStopVNC, h.GenerateRDPFile,
		h.ComputerStartRustDesk, h.RustDeskStart, h.RustDeskStop, h.AgentLogs,
	} {
		e := echo.New()
		recorder := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest(http.MethodPost, "/disabled", nil), recorder)
		err := handler(c)
		var denied *echo.HTTPError
		if !errors.As(err, &denied) || denied.Code != http.StatusForbidden || denied.Message != endpointInboundUnavailable {
			t.Fatal("endpoint inbound operation was not disabled before accessing state", err)
		}
	}
	if _, err := h.GetAgentLogFile(nil, nil, "private.log"); err == nil {
		t.Fatal("log helper bypassed inbound gate")
	}
	h.IndividualAgentService = nil
	if err := h.requireEndpointInbound(); err != nil {
		t.Fatal("legacy mode changed", err)
	}
}

func TestIndividualConsoleRejectsUnsupportedServiceSubjects(t *testing.T) {
	h := &Handler{IndividualAgentService: &openuem.ServiceConnection{}}
	for _, subject := range []string{
		"notification.confirm_email", "notification.reload_settings", "certificates.user",
		"certificates.agent.test", "agent.newconfig", "server.update.test", "ping.agentworker",
		"$JS.API.STREAM.CREATE.AGENTS_STREAM", "agent.>.test", "agent..test", "agent.*.test",
		"agent.a.b.c.d.e", "agent.report.test\nsecret",
	} {
		if err := h.PublishBroker(subject, nil); err == nil || errors.Is(err, nats.ErrConnectionClosed) {
			t.Fatal("unsupported subject reached connection", subject, err)
		}
		if _, err := h.RequestBroker(subject, nil, time.Second); err == nil || errors.Is(err, nats.ErrConnectionClosed) {
			t.Fatal("unsupported request reached connection", subject, err)
		}
	}
	for _, subject := range []string{"agent.report.test", "agent.netbird.refresh.test", "agent.a.b.c.test"} {
		if err := h.brokerSubject(subject); !errors.Is(err, nats.ErrConnectionClosed) {
			t.Fatal("valid command rejected by mode gate", subject, err)
		}
	}
	h.IndividualAgentService = nil
	if err := h.brokerSubject("notification.confirm_email"); !errors.Is(err, nats.ErrConnectionClosed) {
		t.Fatal("legacy subject was mode gated", err)
	}
}
