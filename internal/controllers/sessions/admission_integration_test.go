package sessions_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/nats"
	certificate "github.com/open-uem/openuem-console/internal/controllers/authserver/handlers"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	console "github.com/open-uem/openuem-console/internal/controllers/webserver/handlers"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/ocsp"
)

func TestLocalSessionAdmissionClearsPriorAuthority(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, path := range []string{"pending second factor", "completed login"} {
			for _, same := range []bool{false, true} {
				t.Run(sessionMode(encrypted)+"/"+path+"/same="+map[bool]string{false: "no", true: "yes"}[same], func(t *testing.T) {
					f := newSessionFixture(t, encrypted)
					if err := f.model.CreateInitialSettings(); err != nil {
						t.Fatal(err)
					}
					if err := f.model.CreateDefaultTenantAndSite(); err != nil {
						t.Fatal(err)
					}
					settings, err := f.model.GetAuthenticationSettings()
					if err != nil {
						t.Fatal(err)
					}
					if err = settings.Update().SetUsePasswd(true).Exec(t.Context()); err != nil {
						t.Fatal(err)
					}
					user, err := f.model.Client.User.Create().SetID("login-user").SetName("Owned login").SetPasswd(true).SetHash("owned-validated-hash").SetUse2fa(path == "pending second factor").SetRegister(nats.REGISTER_COMPLETE).Save(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					sm := scs.New()
					sm.Store = f.store
					old, err := sm.Load(t.Context(), "")
					if err != nil {
						t.Fatal(err)
					}
					uid := "previous-user"
					if same {
						uid = user.ID
					}
					sm.Put(old, "uid", uid)
					sm.Put(old, "twofa", true)
					sm.Put(old, "forgot", true)
					sm.Put(old, "oidc-identity", "prior identity")
					sm.Put(old, "password-replacement-kind", "prior grant")
					oldToken, _, err := sm.Commit(old)
					if err != nil {
						t.Fatal(err)
					}
					ctx, err := sm.Load(t.Context(), oldToken)
					if err != nil {
						t.Fatal(err)
					}
					h := &console.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, PublicOrigin: "https://console.test"}
					rec := httptest.NewRecorder()
					c := echo.New().NewContext(httptest.NewRequest("POST", "https://console.test/fixture/admit", nil).WithContext(ctx), rec)
					if path == "pending second factor" {
						err = h.NewSession(c, user)
					} else {
						err = h.AccessGranted(c, user)
					}
					if err != nil {
						t.Fatal(err)
					}
					if sm.Token(ctx) == oldToken {
						t.Error("reauthentication retained the old token")
					}
					for _, key := range []string{"twofa", "forgot", "oidc-identity", "password-replacement-kind"} {
						if (key == "twofa" && sm.GetBool(ctx, key)) || (key != "twofa" && sm.Exists(ctx, key)) {
							t.Error("new login inherited prior authority", key)
						}
					}
					if _, found, err := f.store.FindCtx(t.Context(), oldToken); err != nil || found {
						t.Error("old token survived reauthentication", err)
					}
				})
			}
		}
	}
}

func TestLocalSessionAdmissionFailureDoesNotIssueIdentity(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, failure := range []string{"owner", "confirmation", "owner and cleanup"} {
			t.Run(sessionMode(encrypted)+"/"+failure, func(t *testing.T) {
				f := newSessionFixture(t, encrypted)
				if err := f.model.CreateInitialSettings(); err != nil {
					t.Fatal(err)
				}
				settings, err := f.model.GetAuthenticationSettings()
				if err != nil {
					t.Fatal(err)
				}
				if err = settings.Update().SetUsePasswd(true).Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
				user, err := f.model.Client.User.Create().SetID("login-user").SetName("Owned login").SetPasswd(true).SetHash("owned-validated-hash").SetRegister(nats.REGISTER_COMPLETE).Save(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				table, event := "sessions", "UPDATE OF user_sessions"
				if failure == "confirmation" {
					table, event = "users", "UPDATE OF register"
				}
				if _, err = f.model.DB.Exec(`CREATE FUNCTION fail_owned_admission() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned admission failure'; END $$; CREATE TRIGGER fail_owned_admission BEFORE ` + event + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION fail_owned_admission()`); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(failure, "cleanup") {
					if _, err = f.model.DB.Exec(`CREATE TRIGGER fail_owned_cleanup BEFORE DELETE ON sessions FOR EACH ROW EXECUTE FUNCTION fail_owned_admission()`); err != nil {
						t.Fatal(err)
					}
				}
				sm := scs.New()
				sm.Store = f.store
				h := &console.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, PublicOrigin: "https://console.test"}
				var admissionErr error
				handler := sm.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					c := echo.New().NewContext(r, w)
					admissionErr = h.AccessGranted(c, user)
					if admissionErr != nil {
						c.Error(admissionErr)
					}
				}))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest("POST", "https://console.test/fixture/admit", nil))
				if rec.Code != 500 {
					t.Fatal("admission did not reach the injected storage failure", rec.Code)
				}
				if admissionErr == nil {
					t.Fatal("fault injection did not reject admission")
				}
				for _, cookie := range rec.Result().Cookies() {
					if cookie.Name != sm.Cookie.Name || cookie.Value == "" {
						continue
					}
					ctx, err := sm.Load(t.Context(), cookie.Value)
					if err != nil {
						t.Fatal(err)
					}
					if sm.GetString(ctx, "uid") != "" {
						t.Error("failed login emitted a usable account cookie")
					}
				}
			})
		}
	}
}

func TestSessionAdmissionCleanupOutlivesCanceledRequest(t *testing.T) {
	f := newSessionFixture(t, true)
	sm := scs.New()
	sm.Store = f.store
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx, err := sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	manager := &sessions.SessionManager{Manager: sm, Pool: f.pool}
	rec := httptest.NewRecorder()
	err = manager.Establish(ctx, rec, map[string]any{"uid": "owned-user"}, func(context.Context, string) error {
		cancel()
		return context.Canceled
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("admission hid the original failure", err)
	}
	if sm.GetString(ctx, "uid") != "" || len(rec.Result().Cookies()) != 0 {
		t.Fatal("failed admission retained identity/cookie")
	}
	var count int
	if err = f.model.DB.QueryRow(`SELECT count(*) FROM sessions`).Scan(&count); err != nil || count != 0 {
		t.Fatal("canceled request prevented cleanup", count, err)
	}
}

func TestCertificateSessionAdmissionWithOwnedMutualTLS(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, failure := range []string{"", "owner", "confirmation"} {
			t.Run(sessionMode(encrypted)+"/"+failure, func(t *testing.T) {
				f := newSessionFixture(t, encrypted)
				if err := f.model.CreateInitialSettings(); err != nil {
					t.Fatal(err)
				}
				if err := f.model.CreateDefaultTenantAndSite(); err != nil {
					t.Fatal(err)
				}
				settings, err := f.model.GetAuthenticationSettings()
				if err != nil {
					t.Fatal(err)
				}
				if err = settings.Update().SetUseCertificates(true).Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
				const secret = "JBSWY3DPEHPK3PXP"
				if _, err := f.model.Client.User.Create().SetID("certificate-user").SetName("Owned certificate user").SetUse2fa(failure != "confirmation").SetTotpSecretConfirmed(true).SetTotpSecret(secret).SetRegister(nats.REGISTER_COMPLETE).Save(t.Context()); err != nil {
					t.Fatal(err)
				}
				sm := scs.New()
				sm.Store = f.store
				old, err := sm.Load(t.Context(), "")
				if err != nil {
					t.Fatal(err)
				}
				sm.Put(old, "uid", "certificate-user")
				sm.Put(old, "twofa", true)
				sm.Put(old, "forgot", true)
				sm.Put(old, "oidc-identity", "old identity")
				token, _, err := sm.Commit(old)
				if err != nil {
					t.Fatal(err)
				}
				if failure != "" {
					table, event := "sessions", "UPDATE OF user_sessions"
					if failure == "confirmation" {
						table, event = "users", "UPDATE OF register"
					}
					if _, err = f.model.DB.Exec(`CREATE FUNCTION fail_owned_certificate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned certificate admission failure'; END $$; CREATE TRIGGER fail_owned_certificate BEFORE ` + event + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION fail_owned_certificate()`); err != nil {
						t.Fatal(err)
					}
				}
				ca, credential := ownedConsoleCertificate(t, "certificate-user")
				registerOwnedConsoleCertificate(t, f, credential.Leaf, ca)
				h := &certificate.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, CACert: ca, PublicOrigin: "https://console.test"}
				server := httptest.NewUnstartedServer(sm.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					c := echo.New().NewContext(r, w)
					if err := h.Auth(c); err != nil {
						c.Error(err)
					}
				})))
				roots := x509.NewCertPool()
				roots.AddCert(ca)
				server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
				server.StartTLS()
				defer server.Close()
				client := server.Client()
				client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{credential}
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
				request, err := http.NewRequestWithContext(t.Context(), "GET", server.URL+"/auth", nil)
				if err != nil {
					t.Fatal(err)
				}
				request.AddCookie(&http.Cookie{Name: sm.Cookie.Name, Value: token})
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if failure == "" && response.StatusCode != http.StatusFound {
					t.Fatal("owned certificate login failed", response.StatusCode)
				}
				if failure != "" && response.StatusCode != http.StatusInternalServerError {
					t.Fatal("certificate admission ignored injected failure", response.StatusCode)
				}
				issued := false
				latestToken := ""
				for _, cookie := range response.Cookies() {
					if cookie.Name != sm.Cookie.Name || cookie.Value == "" {
						continue
					}
					ctx, err := sm.Load(t.Context(), cookie.Value)
					if err != nil {
						t.Fatal(err)
					}
					uid := sm.GetString(ctx, "uid")
					if failure != "" && uid != "" {
						t.Fatal("failed certificate login issued identity")
					}
					if failure == "" {
						issued = true
						latestToken = cookie.Value
						if uid != "certificate-user" || cookie.Value == token || sm.GetBool(ctx, "twofa") || sm.Exists(ctx, "forgot") || sm.Exists(ctx, "oidc-identity") {
							t.Fatal("certificate login inherited old authority")
						}
					}
				}
				if failure == "" && !issued {
					t.Fatal("certificate login did not issue a fresh pending MFA session")
				}
				if failure == "" {
					ctx, err := sm.Load(t.Context(), latestToken)
					if err != nil {
						t.Fatal(err)
					}
					proof, err := loginproof.Read(sm.GetString(ctx, loginproof.SessionKey), "certificate-user", time.Now())
					if err != nil || proof.Method != loginproof.Certificate || proof.Credential != loginproof.Digest(string(credential.Leaf.Raw)) {
						t.Fatal("TLS identity did not bind the MFA flow", err)
					}
					code, err := totp.GenerateCode(secret, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					req := httptest.NewRequest("POST", "https://console.test/fixture/mfa", strings.NewReader(url.Values{"confirm-code": {code}}.Encode())).WithContext(ctx)
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					c := echo.New().NewContext(req, httptest.NewRecorder())
					web := &console.Handler{Model: f.model, SessionManager: h.SessionManager, EncryptionMasterKey: f.key, PublicOrigin: "https://console.test"}
					if err = web.LoginTOTPValidate(c); err != nil {
						t.Fatal("certificate-bound MFA failed", err)
					}
					if !sm.GetBool(ctx, "twofa") || sm.Exists(ctx, loginproof.SessionKey) {
						t.Fatal("certificate MFA did not finish its primary flow")
					}
				}
				if _, found, err := f.store.FindCtx(t.Context(), token); err != nil || found {
					t.Fatal("old certificate session was not retired", err)
				}
			})
		}
	}
}

func ownedConsoleCertificate(t *testing.T, uid string, expires ...time.Time) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Owned console CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	if len(expires) > 1 {
		template.NotAfter = expires[1]
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	response, err := ocsp.CreateResponse(ca, ca, ocsp.Response{SerialNumber: big.NewInt(2), Status: ocsp.Good, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, key)
	if err != nil {
		t.Fatal(err)
	}
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(response)
	}))
	t.Cleanup(responder.Close)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: uid}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, OCSPServer: []string{responder.URL}}
	if len(expires) > 0 {
		leaf.NotAfter = expires[0]
	}
	der, err = x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey, Leaf: parsed}
}
