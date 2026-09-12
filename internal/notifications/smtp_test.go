package notifications

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wneessen/go-mail/smtp"
)

type smtpFixture struct {
	config  smtpSettings
	roots   *x509.CertPool
	message chan string
	closed  chan struct{}
}

func smtpPeer(t *testing.T, mode, behavior string) smtpFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Loopback SMTP"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	n, _ := strconv.Atoi(port)
	f := smtpFixture{config: smtpSettings{host: "127.0.0.1", port: n, from: "OpenUEM <from@example.test>", encryption: mode, auth: "NOAUTH"}, roots: roots, message: make(chan string, 1), closed: make(chan struct{})}
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-f.closed:
		case <-time.After(3 * time.Second):
			t.Error("SMTP peer did not stop")
		}
	})
	go func() {
		defer close(f.closed)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if behavior == "stall_greeting" {
			_, _ = io.Copy(io.Discard, conn)
			return
		}
		secure := false
		if mode == "smtps" {
			conn = tls.Server(conn, tlsConfig)
			secure = true
		}
		p := textproto.NewConn(conn)
		if err = p.PrintfLine("220 loopback ESMTP"); err != nil {
			return
		}
		for {
			line, err := p.ReadLine()
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO "):
				_ = p.PrintfLine("250-loopback")
				if !secure && behavior != "no_starttls" {
					_ = p.PrintfLine("250-STARTTLS")
				}
				_ = p.PrintfLine("250 AUTH LOGIN PLAIN XOAUTH2 SCRAM-SHA-256")
			case line == "STARTTLS":
				if behavior == "no_starttls" {
					_ = p.PrintfLine("454 unavailable")
					continue
				}
				_ = p.PrintfLine("220 Ready")
				conn = tls.Server(conn, tlsConfig)
				secure = true
				p = textproto.NewConn(conn)
			case strings.HasPrefix(line, "AUTH "):
				if !secure {
					t.Error("credentials sent without TLS")
					return
				}
				switch {
				case line == "AUTH LOGIN":
					_ = p.PrintfLine("334 %s", base64.StdEncoding.EncodeToString([]byte("Username:")))
					user, _ := p.ReadLine()
					_ = p.PrintfLine("334 %s", base64.StdEncoding.EncodeToString([]byte("Password:")))
					password, _ := p.ReadLine()
					if user != base64.StdEncoding.EncodeToString([]byte("user")) || password != base64.StdEncoding.EncodeToString([]byte("password")) {
						t.Error("incorrect LOGIN exchange")
						return
					}
				case strings.HasPrefix(line, "AUTH PLAIN "):
					value, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
					if string(value) != "\x00user\x00password" {
						t.Error("incorrect PLAIN exchange")
						return
					}
				case strings.HasPrefix(line, "AUTH XOAUTH2 "):
					value, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH XOAUTH2 "))
					if string(value) != "user=user\x01auth=Bearer password\x01\x01" {
						t.Error("incorrect XOAUTH2 exchange")
						return
					}
				case line == "AUTH SCRAM-SHA-256":
					_ = p.PrintfLine("334 ")
					initial, _ := p.ReadLine()
					decoded, _ := base64.StdEncoding.DecodeString(initial)
					parts := strings.Split(string(decoded), ",r=")
					if len(parts) != 2 {
						t.Error("invalid SCRAM initial message")
						return
					}
					if behavior == "scram_cost" {
						_ = p.PrintfLine("334 %s", base64.StdEncoding.EncodeToString([]byte("r="+parts[1]+"server,s=c2FsdA==,i=2147483647")))
						_, _ = p.ReadLine()
						return
					}
					serverFirst := "r=" + parts[1] + "server,s=c2FsdA==,i=4096"
					_ = p.PrintfLine("334 %s", base64.StdEncoding.EncodeToString([]byte(serverFirst)))
					response, _ := p.ReadLine()
					final, _ := base64.StdEncoding.DecodeString(response)
					proofParts := strings.Split(string(final), ",p=")
					if len(proofParts) != 2 || proofParts[0] != "c=biws,r="+parts[1]+"server" {
						t.Error("invalid SCRAM final message")
						return
					}
					salted, _ := pbkdf2.Key(sha256.New, "password", []byte("salt"), 4096, 32)
					mac := func(key []byte, value string) []byte {
						h := hmac.New(sha256.New, key)
						_, _ = h.Write([]byte(value))
						return h.Sum(nil)
					}
					clientKey := mac(salted, "Client Key")
					stored := sha256.Sum256(clientKey)
					authMessage := strings.TrimPrefix(string(decoded), "n,,") + "," + serverFirst + "," + proofParts[0]
					clientSignature := mac(stored[:], authMessage)
					for i := range clientKey {
						clientKey[i] ^= clientSignature[i]
					}
					proof, _ := base64.StdEncoding.DecodeString(proofParts[1])
					if !hmac.Equal(proof, clientKey) {
						t.Error("invalid SCRAM proof")
						return
					}
					serverSignature := base64.StdEncoding.EncodeToString(mac(mac(salted, "Server Key"), authMessage))
					_ = p.PrintfLine("334 %s", base64.StdEncoding.EncodeToString([]byte("v="+serverSignature)))
					if response, err = p.ReadLine(); err != nil || response != "" {
						t.Error("SCRAM server verification acknowledgement")
						return
					}
				default:
					t.Error("unexpected authentication mechanism")
					return
				}
				_ = p.PrintfLine("235 authenticated")
			case strings.HasPrefix(line, "MAIL FROM:"):
				if !strings.Contains(line, "<from@example.test>") {
					t.Error("wrong envelope sender")
				}
				_ = p.PrintfLine("250 OK")
			case strings.HasPrefix(line, "RCPT TO:"):
				if line != "RCPT TO:<recipient@example.test>" {
					t.Error("wrong envelope recipient")
				}
				_ = p.PrintfLine("250 OK")
			case line == "DATA":
				_ = p.PrintfLine("354 send data")
				body, err := io.ReadAll(p.DotReader())
				if err != nil {
					return
				}
				if behavior == "stall_data" {
					_, _ = io.Copy(io.Discard, conn)
					return
				}
				if behavior == "reject_data" {
					_ = p.PrintfLine("550 synthetic rejected response with private detail")
					return
				}
				f.message <- string(body)
				_ = p.PrintfLine("250 accepted")
				return // A missing QUIT response must not turn acceptance into failure.
			case line == "*":
				return
			default:
				t.Errorf("unexpected SMTP command %q", line)
				return
			}
		}
	}()
	return f
}

func fixtureMessage() Message {
	return Message{ID: "20000000-0000-0000-0000-000000000001", To: "recipient@example.test", Subject: "Certificate reminder", CreatedAt: time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC), Text: "Plain-text reminder", HTML: "<html lang=\"en\"><body>Reminder</body></html>"}
}

func TestSMTPTransportAndAuthentication(t *testing.T) {
	for _, tc := range []struct{ mode, auth string }{{"none", "NOAUTH"}, {"none", "LOGIN"}, {"starttls", "LOGIN"}, {"smtps", "PLAIN"}, {"starttls", "XOAUTH2"}, {"starttls", "SCRAM-SHA-256"}} {
		t.Run(tc.mode+"_"+tc.auth, func(t *testing.T) {
			f := smtpPeer(t, tc.mode, "")
			cfg := f.config
			cfg.auth = tc.auth
			if tc.mode != "none" {
				cfg.username = "user"
				cfg.password = "password"
			}
			if err := sendSMTP(t.Context(), cfg, fixtureMessage(), f.roots); err != nil {
				t.Fatal(err)
			}
			body := <-f.message
			m, err := mail.ReadMessage(strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			if m.Header.Get("Message-ID") != "<20000000-0000-0000-0000-000000000001@openuem.invalid>" || !strings.Contains(m.Header.Get("Content-Type"), "multipart/alternative") || m.Header.Get("To") != "<recipient@example.test>" {
				t.Fatalf("unexpected MIME headers: %+v", m.Header)
			}
		})
	}
}

func TestSMTPTrustFailuresAndCancellation(t *testing.T) {
	for _, behavior := range []string{"untrusted", "wrong_hostname", "no_starttls", "reject_data", "stall_greeting", "stall_data", "scram_cost"} {
		t.Run(behavior, func(t *testing.T) {
			mode := "starttls"
			if behavior == "stall_greeting" {
				mode = "none"
			}
			f := smtpPeer(t, mode, behavior)
			cfg := f.config
			roots := f.roots
			if behavior == "untrusted" {
				roots = nil
			}
			if behavior == "wrong_hostname" {
				cfg.host = "localhost"
			}
			if behavior == "scram_cost" {
				cfg.auth = "SCRAM-SHA-256"
				cfg.username = "user"
				cfg.password = "password"
			}
			ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
			defer cancel()
			if err := sendSMTP(ctx, cfg, fixtureMessage(), roots); !errors.Is(err, ErrDelivery) {
				t.Fatal("expected fixed delivery error", err)
			}
			select {
			case <-f.message:
				t.Error("rejected/cancelled send accepted")
			default:
			}
		})
	}
}

func TestSMTPRejectsUnsafeConfigurationBeforeDial(t *testing.T) {
	base := smtpSettings{host: "127.0.0.1", port: 1, from: "from@example.test", auth: "LOGIN", encryption: "starttls", username: "user", password: "password"}
	for _, change := range []func(*smtpSettings){func(c *smtpSettings) { c.encryption = "none" }, func(c *smtpSettings) { c.host = "https://example.test" }, func(c *smtpSettings) { c.port = 0 }, func(c *smtpSettings) { c.from = "from@example.test\r\nBcc: attacker@example.test" }, func(c *smtpSettings) { c.auth = "UNKNOWN" }, func(c *smtpSettings) { c.password = "" }} {
		cfg := base
		change(&cfg)
		if err := sendSMTP(t.Context(), cfg, fixtureMessage(), nil); !errors.Is(err, ErrConfiguration) {
			t.Fatal("unsafe configuration was dialed", err)
		}
	}
}

func TestSMTPPasswordCompatibilityAndCorruption(t *testing.T) {
	key := strings.Repeat("k", 32)
	block, _ := aes.NewCipher([]byte(key))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	sealed := gcm.Seal(nonce, nonce, []byte("fixture-password"), nil)
	value := hex.EncodeToString(sealed)
	if got, err := smtpPassword(value, key); err != nil || got != "fixture-password" {
		t.Fatal("encrypted SMTP password", err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := smtpPassword(hex.EncodeToString(sealed), key); !errors.Is(err, ErrConfiguration) {
		t.Fatal("corrupt encrypted password treated as plaintext", err)
	}
	for _, plain := range []string{"", "legacy-password", "abc", "abcd"} {
		if got, err := smtpPassword(plain, key); err != nil || got != plain {
			t.Fatal("legacy password compatibility", err)
		}
	}
	if _, err := smtpPassword(value, "wrong-key"); !errors.Is(err, ErrConfiguration) {
		t.Fatal("wrong key accepted")
	}
}

func TestSMTPAuthenticationWorkIsBounded(t *testing.T) {
	a := &boundedAuth{Auth: smtp.XOAuth2Auth("user", "token"), ctx: t.Context()}
	if _, err := a.Next(make([]byte, 8193), true); err == nil {
		t.Fatal("oversized challenge accepted")
	}
	a = &boundedAuth{Auth: smtp.XOAuth2Auth("user", "token"), ctx: t.Context()}
	for range 8 {
		_, _ = a.Next(nil, true)
	}
	if _, err := a.Next(nil, true); err == nil {
		t.Fatal("unbounded challenge count")
	}
}
