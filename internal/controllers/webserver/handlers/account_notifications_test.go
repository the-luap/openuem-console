package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	_ "github.com/mattn/go-sqlite3"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/open-uem/ent/enttest"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/utils"
	"github.com/stretchr/testify/require"
)

func TestAccountNotificationsUseConfiguredOriginAndRetainPasswordToken(t *testing.T) {
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	require.NoError(t, err)
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	require.True(t, broker.ReadyForConnections(5*time.Second))
	nc, err := nats.Connect(broker.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)
	sub, err := nc.SubscribeSync("notification.confirm_email")
	require.NoError(t, err)
	require.NoError(t, nc.Flush())
	client := enttest.Open(t, "sqlite3", "file:account-notifications?mode=memory&_fk=1")
	t.Cleanup(func() { client.Close() })
	model := &models.Model{Client: client}
	user, err := client.User.Create().SetID("owned-invitation-user").SetName("Owned invitation user").SetEmail("recipient@example.test").Save(t.Context())
	require.NoError(t, err)
	for _, origin := range []struct {
		name string
		h    *Handler
		want string
	}{
		{"public", &Handler{PublicOrigin: "https://console.example.test:8443"}, "https://console.example.test:8443"},
		{"proxy", &Handler{ReverseProxyServer: "proxy.example.test:8443"}, "https://proxy.example.test:8443"},
		{"direct", &Handler{ServerName: "console.internal", ConsolePort: "1323"}, "https://console.internal:1323"},
	} {
		h := origin.h
		h.Model, h.NATSConnection, h.JWTKey = model, nc, strings.Repeat("j", 32)
		for _, encrypted := range []bool{false, true} {
			h.EncryptionMasterKey = ""
			if encrypted {
				h.EncryptionMasterKey = strings.Repeat("k", 32)
			}
			for _, requestOrigin := range []string{"", origin.want, "https://untrusted.invalid"} {
				for _, kind := range []string{"confirmation", "password"} {
					t.Run(fmt.Sprintf("%s/%s/%s/encrypted=%t", origin.name, kind, requestOrigin, encrypted), func(t *testing.T) {
						req := httptest.NewRequest(http.MethodPost, "/owned-notification", nil)
						req.Header.Set("Origin", requestOrigin)
						c := echo.New().NewContext(req, httptest.NewRecorder())
						if kind == "confirmation" {
							require.NoError(t, h.sendConfirmationEmail(c, user))
						} else {
							require.NoError(t, h.sendLinkToGeneratePassword(c, user))
						}
						message, err := sub.NextMsg(5 * time.Second)
						require.NoError(t, err)
						var notification openuem.Notification
						require.NoError(t, json.Unmarshal(message.Data, &notification))
						require.Equal(t, user.Email, notification.To)
						target, err := url.Parse(notification.MessageActionURL)
						require.NoError(t, err)
						if target.Scheme+"://"+target.Host != origin.want || target.User != nil || target.Fragment != "" {
							t.Error("notification did not use the configured console origin")
						}
						encoded, subject := strings.TrimPrefix(target.Path, "/auth/confirm/"), "Email Confirmation"
						if kind == "password" {
							require.Equal(t, "/login/new", target.Path)
							encoded, subject = target.Query().Get("token"), "New password"
							stored, err := client.User.Get(t.Context(), user.ID)
							require.NoError(t, err)
							saved := stored.NewUserToken
							if encrypted {
								require.NotEqual(t, encoded, saved, "invitation should be encrypted at rest")
								saved, err = utils.DecryptSensitiveField(saved, h.EncryptionMasterKey)
								require.NoError(t, err)
							}
							if saved == "" || saved != encoded {
								t.Error("password notification lost its exact stored invitation")
							}
						} else {
							require.True(t, strings.HasPrefix(target.Path, "/auth/confirm/"))
						}
						claims := &jwt.RegisteredClaims{}
						_, err = jwt.ParseWithClaims(encoded, claims, func(*jwt.Token) (any, error) { return []byte(h.JWTKey), nil }, jwt.WithValidMethods([]string{"HS512"}), jwt.WithExpirationRequired(), jwt.WithIssuer("OpenUEM"), jwt.WithSubject(subject))
						require.NoError(t, err)
						require.Equal(t, user.ID, claims.ID)
					})
				}
			}
		}
	}
}
