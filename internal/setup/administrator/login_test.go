package administrator

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/controllers/router"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/controllers/webserver/handlers"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/setup/secrets"
	"github.com/open-uem/utils"
)

func TestProtectedAdministratorConsolePasswordLifecycle(t *testing.T) {
	m := accountModel(t)
	ctx := context.Background()
	if err := m.CreateInitialSettings(); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateDefaultTenantAndSite(); err != nil {
		t.Fatal(err)
	}
	initialPassword := testPassword
	key, jwtKey := strings.Repeat("k", 32), strings.Repeat("j", 32)
	installation := strings.Repeat("1", 32)
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		path := filepath.Join(t.TempDir(), "provisioning")
		provisioned, err := secrets.Initialize(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		installation = provisioned.Installation
		credentials, err := secrets.Load(secrets.Inputs{Installation: installation, JWTFile: filepath.Join(path, secrets.JWTFile), MasterFile: filepath.Join(path, secrets.MasterFile), Required: true})
		if err != nil {
			t.Fatal(err)
		}
		key, jwtKey = credentials.Master, credentials.JWT
		data, err := os.ReadFile(filepath.Join(path, secrets.PasswordFile))
		if err != nil {
			t.Fatal(err)
		}
		initialPassword = string(data)
		clear(data)
	}
	credentials := secrets.Runtime{Installation: installation, JWT: jwtKey, Master: key}
	if err := secrets.CheckBinding(ctx, m.DB, credentials); err != nil {
		t.Fatal("generated credentials could not bind the fresh database", err)
	}
	config := Config{UserID: "first-admin", PasswordFile: passwordFile(t, initialPassword)}
	if created, err := Initialize(ctx, m.DB, config); err != nil || !created {
		t.Fatal("bootstrap failed", created, err)
	}
	sm := sessions.New(m.databaseURL, 30, key)
	defer sm.Close()
	permissions, _ := access.NewStore(m.DB)
	h := &handlers.Handler{Model: m.Model, Access: permissions, SessionManager: sm, EncryptionMasterKey: key, PublicOrigin: "https://uem.example.test", AuthLogger: log.New(io.Discard, "", 0)}
	e := router.New(sm, "uem.example.test", "443", "1M")
	h.Register(e, 3)
	cookies := map[string]*http.Cookie{}
	request := func(method, path string, form url.Values, expected ...int) *httptest.ResponseRecorder {
		t.Helper()
		if form == nil {
			form = url.Values{}
		}
		if method == http.MethodPost {
			if cookie := cookies["__Host-openuem-csrf"]; cookie != nil {
				form.Set("csrf", cookie.Value)
			}
		}
		req := httptest.NewRequest(method, "https://uem.example.test"+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		for _, cookie := range rec.Result().Cookies() {
			cookies[cookie.Name] = cookie
		}
		if (len(expected) != 0 && rec.Code != expected[0]) || (len(expected) == 0 && rec.Code != http.StatusOK && !(path == "/login/userpass" && rec.Code == http.StatusFound)) {
			t.Fatal("console password route failed", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), initialPassword) {
			t.Fatal("console rendered its initial password")
		}
		return rec
	}
	request(http.MethodGet, "/login", nil)
	rec := request(http.MethodPost, "/login/userpass", url.Values{"username": {config.UserID}, "password": {initialPassword}})
	if !strings.Contains(rec.Body.String(), "confirm-password") || rec.Header().Get("Location") != "" {
		t.Fatal("first login did not require password replacement")
	}
	loaded, err := sm.Manager.Load(ctx, cookies[sm.Manager.Cookie.Name].Value)
	if err != nil || sm.Manager.GetString(loaded, "uid") != config.UserID || !sm.Manager.GetBool(loaded, "forgot") {
		t.Fatal("first login received an unrestricted or missing session", err)
	}
	firstBrowser := cookies
	cookies = map[string]*http.Cookie{}
	request(http.MethodGet, "/login", nil)
	request(http.MethodPost, "/login/userpass", url.Values{"username": {config.UserID}, "password": {initialPassword}})
	staleBrowser := cookies
	cookies = firstBrowser
	newPassword := "MyNew-Administrator_Password-987654321!"
	request(http.MethodPost, "/login/changepass", url.Values{"password": {newPassword}, "confirm-password": {newPassword}})
	u, err := m.Client.User.Get(ctx, config.UserID)
	if err != nil || u.Register != "users.completed" {
		t.Fatal("password replacement did not complete", err)
	}
	if match, err := argon2id.ComparePasswordAndHash(newPassword, u.Hash); err != nil || !match {
		t.Fatal("replacement password was not persisted", err)
	}
	if match, err := argon2id.ComparePasswordAndHash(initialPassword, u.Hash); err != nil || match {
		t.Fatal("bootstrap password remained valid", err)
	}
	if err := os.Remove(config.PasswordFile); err != nil {
		t.Fatal(err)
	}
	if err := secrets.CheckBinding(ctx, m.DB, credentials); err != nil {
		t.Fatal("restart rejected the original generated credentials", err)
	}
	if created, err := Initialize(ctx, m.DB, config); err != nil || created {
		t.Fatal("restart reset the first login", created, err)
	}
	cookies = staleBrowser
	request(http.MethodPost, "/login/changepass", url.Values{"password": {"Stale-Session-Replacement-123456!"}, "confirm-password": {"Stale-Session-Replacement-123456!"}}, http.StatusForbidden)
	cookies = firstBrowser
	request(http.MethodPost, "/login/userpass", url.Values{"username": {config.UserID}, "password": {initialPassword}})
	rec = request(http.MethodPost, "/login/userpass", url.Values{"username": {config.UserID}, "password": {newPassword}})
	if !strings.HasPrefix(rec.Header().Get("Location"), "https://uem.example.test/tenant/") || !strings.HasSuffix(rec.Header().Get("Location"), "/dashboard") {
		t.Fatal("replacement password could not complete normal console login")
	}
	loaded, err = sm.Manager.Load(ctx, cookies[sm.Manager.Cookie.Name].Value)
	if err != nil || sm.Manager.GetString(loaded, "uid") != config.UserID || sm.Manager.GetBool(loaded, "forgot") {
		t.Fatal("replacement login did not create a normal session", err)
	}
	// Exercise the real email recovery routes using a local broker subscription;
	// no mail is sent. Merely requesting a code must not authorize replacement.
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	defer func() { broker.Shutdown(); broker.WaitForShutdown() }()
	if !broker.ReadyForConnections(time.Second) {
		t.Fatal("local notification broker did not start")
	}
	connection, err := nats.Connect(broker.ClientURL(), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	h.NATSConnection = connection
	notifications, err := connection.SubscribeSync("notification.confirm_email")
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.Flush(); err != nil {
		t.Fatal(err)
	}
	if err = m.Client.User.UpdateOneID(config.UserID).SetEmail("first-admin@example.test").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	nextCode := func() string {
		t.Helper()
		message, err := notifications.NextMsg(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		var notification openuem.Notification
		if err := json.Unmarshal(message.Data, &notification); err != nil {
			t.Fatal(err)
		}
		link, err := url.Parse(notification.MessageActionURL)
		if err != nil || link.Host != "uem.example.test" || link.Scheme != "https" {
			t.Fatal("recovery link did not use the canonical console origin", err)
		}
		return link.Query().Get("code")
	}
	request(http.MethodPost, "/login/forgot", url.Values{"email": {"first-admin@example.test"}})
	code := nextCode()
	replacement := "Verified-Recovery-Password-123456!"
	replacementForm := func() url.Values { return url.Values{"password": {replacement}, "confirm-password": {replacement}} }
	request(http.MethodPost, "/login/changepass", replacementForm(), http.StatusForbidden)
	request(http.MethodPost, "/login/forgotverify", url.Values{"confirm-code": {"WRONG-CODE"}}, http.StatusUnauthorized)
	request(http.MethodPost, "/login/changepass", replacementForm(), http.StatusForbidden)
	request(http.MethodPost, "/login/forgotverify", url.Values{"confirm-code": {code}})
	// A newer code invalidates a previously verified replacement session.
	newerHash, err := argon2id.CreateHash("NEWER-CODE", argon2id.DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.SaveForgotCode(config.UserID, newerHash); err != nil {
		t.Fatal(err)
	}
	request(http.MethodPost, "/login/changepass", replacementForm())
	u, err = m.Client.User.Get(ctx, config.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if matches, err := argon2id.ComparePasswordAndHash(newPassword, u.Hash); err != nil || !matches {
		t.Fatal("superseded recovery proof changed the password", err)
	}
	request(http.MethodPost, "/login/forgot", url.Values{"email": {"first-admin@example.test"}})
	code = nextCode()
	request(http.MethodPost, "/login/forgotverify", url.Values{"confirm-code": {code}})
	request(http.MethodPost, "/login/changepass", replacementForm())
	u, err = m.Client.User.Get(ctx, config.UserID)
	if err != nil || u.ForgotPasswordCode != "" {
		t.Fatal("recovery did not consume its code", err)
	}
	if matches, err := argon2id.ComparePasswordAndHash(replacement, u.Hash); err != nil || !matches {
		t.Fatal("verified recovery did not persist its password", err)
	}

	// An authenticated invitation remains usable until one password is committed;
	// scanning its GET link does not consume it. Bind the session to the exact
	// encrypted invitation record and consume it with the password transaction.
	h.JWTKey = jwtKey
	if err := m.Client.User.Create().SetID("invited-admin").SetName("Invited administrator").SetPasswd(true).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, handlers.MyCustomClaims{RegisteredClaims: jwt.RegisteredClaims{ID: "invited-admin", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}})
	encoded, err := token.SignedString([]byte(h.JWTKey))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := utils.EncryptSensitiveField(encoded, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SaveNewAccountToken("invited-admin", encrypted); err != nil {
		t.Fatal(err)
	}
	cookies = map[string]*http.Cookie{}
	rec = request(http.MethodGet, "/login/new?token="+url.QueryEscape(encoded), nil)
	if !strings.Contains(rec.Body.String(), "confirm-password") {
		t.Fatal("valid invitation could not open password replacement")
	}
	invited, err := m.Client.User.Get(ctx, "invited-admin")
	if err != nil || invited.NewUserToken != encrypted {
		t.Fatal("opening an invitation consumed it before password commit", err)
	}
	request(http.MethodPost, "/login/changepass", replacementForm())
	invited, err = m.Client.User.Get(ctx, "invited-admin")
	if err != nil || invited.NewUserToken != "" {
		t.Fatal("invitation was not consumed with password replacement", err)
	}
	if matches, err := argon2id.ComparePasswordAndHash(replacement, invited.Hash); err != nil || !matches {
		t.Fatal("invited password did not persist", err)
	}
	request(http.MethodGet, "/login/new?token="+url.QueryEscape(encoded), nil, http.StatusForbidden)

}
