package apple

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestAPNsConnectionGatesCredentialReplacement(t *testing.T) {
	for _, method := range []string{"request", "legacy"} {
		t.Run(method, func(t *testing.T) {
			s := testStore(t)
			ctx := t.Context()
			old := testSettings(t, s, 1)
			oldMetadata, err := s.SettingsMetadata(ctx, 1)
			if err != nil {
				t.Fatal(err)
			}
			request := newTestPushRequest(t, s, 1)
			sibling := newTestPushRequest(t, s, 1)
			fixture := newAPNsTLSFixture(t, apnsProductionHost)
			certificate := issueTestPushCertificate(t, s, 1, request.ID, old.Topic, time.Now().Add(time.Hour))
			candidate := *old
			if method == "legacy" {
				issuer, signer := testPushCA(t)
				template := pushLeafTemplate()
				template.Subject.ExtraNames[0].Value = old.Topic
				key := fixture.client.PrivateKey.(*ecdsa.PrivateKey)
				certificate = signPushLeaf(t, template, issuer, &key.PublicKey, signer)
				keyDER, err := x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					t.Fatal(err)
				}
				candidate.PushKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
			}
			candidate.PushCertificate = certificate
			block, _ := pem.Decode(certificate)
			fingerprint := digest(block.Bytes)
			var reject atomic.Bool
			reject.Store(true)
			var connections atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("replacement sent a device request") }))
			server.EnableHTTP2 = true
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{Certificates: []tls.Certificate{fixture.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: fixture.clientRoots, MinVersion: tls.VersionTLS13, VerifyConnection: func(state tls.ConnectionState) error {
				connections.Add(1)
				if len(state.PeerCertificates) != 1 || !bytes.Equal(state.PeerCertificates[0].Raw, block.Bytes) {
					t.Error("replacement checked a different credential")
					return errors.New("wrong candidate")
				}
				if reject.Load() {
					return errors.New("test peer rejects candidate")
				}
				return nil
			}}
			server.StartTLS()
			defer server.Close()
			s.checkPushConnection = func(ctx context.Context, c *Settings) error {
				pair, err := tls.X509KeyPair(c.PushCertificate, c.PushKey)
				if err != nil {
					return err
				}
				return probeAPNsConnection(ctx, pair, loopbackAPNsDialer(t, server.Listener.Addr().String()), fixture.serverRoots)
			}
			perform := func() error {
				if method == "request" {
					return s.ImportPushCertificate(ctx, 1, request.ID, certificate, "test-admin")
				}
				return s.Configure(ctx, candidate, "test-admin")
			}
			assertUnchanged := func() {
				t.Helper()
				current, err := s.Settings(ctx, 1)
				if err != nil || !bytes.Equal(current.PushCertificate, old.PushCertificate) || !bytes.Equal(current.PushKey, old.PushKey) || !bytes.Equal(current.CACertificate, old.CACertificate) || !bytes.Equal(current.CAKey, old.CAKey) {
					t.Fatal("failure changed active credentials", err)
				}
				metadata, err := s.SettingsMetadata(ctx, 1)
				if err != nil || metadata.PushFingerprint != oldMetadata.PushFingerprint || metadata.PushCheckedAt == nil || !metadata.PushCheckedAt.Equal(*oldMetadata.PushCheckedAt) {
					t.Fatal("failure changed connection evidence", err)
				}
				var revision int
				if err = s.db.QueryRow(`SELECT push_revision FROM mdm_apple_settings WHERE tenant_id=1`).Scan(&revision); err != nil || revision != 1 {
					t.Fatal("failure advanced active generation", revision, err)
				}
				for _, id := range []string{request.ID, sibling.ID} {
					var pending bool
					if err = s.db.QueryRow(`SELECT status='pending' AND encrypted_key IS NOT NULL FROM mdm_apple_push_requests WHERE id=$1`, id).Scan(&pending); err != nil || !pending {
						t.Fatal("failure consumed or superseded request", err)
					}
				}
				var count int
				if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE action='apple.push_connection.verify' AND resource_id=$1`, fingerprint).Scan(&count); err != nil || count != 0 {
					t.Fatal("failure retained a success audit", count, err)
				}
			}
			if err = perform(); err != ErrPushConnection {
				t.Fatal("TLS rejection did not gate replacement", err)
			}
			assertUnchanged()
			reject.Store(false)
			// Fail after the new settings, connection evidence and request changes.
			if _, err = s.db.Exec(`CREATE FUNCTION reject_checked_settings() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.settings.save' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_checked_settings BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_checked_settings()`); err != nil {
				t.Fatal(err)
			}
			if err = perform(); err == nil {
				t.Fatal("audit failure committed a replacement")
			}
			assertUnchanged()
			if _, err = s.db.Exec(`DROP TRIGGER reject_checked_settings ON mdm_apple_audit`); err != nil {
				t.Fatal(err)
			}
			if err = perform(); err != nil {
				t.Fatal("corrected connection did not allow retry", err)
			}
			current, err := s.Settings(ctx, 1)
			if err != nil || !bytes.Equal(current.PushCertificate, certificate) || !bytes.Equal(current.CACertificate, old.CACertificate) || !bytes.Equal(current.CAKey, old.CAKey) {
				t.Fatal("successful replacement lost certificate or CA", err)
			}
			metadata, err := s.SettingsMetadata(ctx, 1)
			if err != nil || metadata.PushCheckedAt == nil || metadata.PushFingerprint != fingerprint || !metadata.PushCheckedAt.After(*oldMetadata.PushCheckedAt) {
				t.Fatal("connection evidence not bound to imported certificate", err)
			}
			encoded, err := json.Marshal(metadata)
			if err != nil || bytes.Contains(encoded, []byte(fingerprint)) {
				t.Fatal("connection evidence leaked into device JSON", err)
			}
			for _, id := range []string{request.ID, sibling.ID} {
				var removed bool
				if err = s.db.QueryRow(`SELECT encrypted_key IS NULL AND status<>'pending' FROM mdm_apple_push_requests WHERE id=$1`, id).Scan(&removed); err != nil || !removed {
					t.Fatal("success kept stale request keys", err)
				}
			}
			var count int
			if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE action='apple.push_connection.verify' AND resource_id=$1`, fingerprint).Scan(&count); err != nil || count != 1 {
				t.Fatal("missing or duplicated success audit", count, err)
			}
			if connections.Load() != 3 {
				t.Fatal("every attempt did not use a fresh connection", connections.Load())
			}
		})
	}
}

func TestAPNsMissingCheckerCannotActivate(t *testing.T) {
	s := testStore(t)
	request := newTestPushRequest(t, s, 1)
	certificate := issueTestPushCertificate(t, s, 1, request.ID, "com.apple.mgmt.test", time.Now().Add(time.Hour))
	s.checkPushConnection = nil
	if err := s.ImportPushCertificate(t.Context(), 1, request.ID, certificate, "test-admin"); err != ErrPushConnection {
		t.Fatal("missing check activated credentials", err)
	}
	if _, err := s.SettingsMetadata(t.Context(), 1); !errors.Is(err, ErrNotFound) {
		t.Fatal("failed initial setup persisted", err)
	}
	if _, err := s.PushRequestCSR(t.Context(), 1, request.ID, "test-admin"); err != nil {
		t.Fatal("failed initial setup consumed request", err)
	}
}
