// Package notifications provides bounded SMTP delivery for durable console jobs.
package notifications

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"

	gomail "github.com/wneessen/go-mail"
	"github.com/wneessen/go-mail/smtp"
)

var (
	ErrConfiguration = errors.New("SMTP settings are missing or invalid")
	ErrDelivery      = errors.New("SMTP delivery failed")
)

type Message struct {
	ID, To, Subject, Text, HTML string
	CreatedAt                   time.Time
}

type Queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type smtpSettings struct {
	host, username, password, auth, from, encryption string
	port                                             int
}

// Send uses the organization's settings. Global settings are used only when no
// organization row exists; an incomplete organization configuration fails closed.
// Nothing is created or updated as a side effect of reading configuration.
func Send(ctx context.Context, q Queryer, tenant int, masterKey string, m Message) error {
	cfg, err := readSettings(ctx, q, tenant)
	if err != nil {
		return ErrConfiguration
	}
	if cfg.auth != "NOAUTH" {
		cfg.password, err = smtpPassword(cfg.password, masterKey)
		if err != nil {
			return ErrConfiguration
		}
	}
	return sendSMTP(ctx, cfg, m, nil)
}

func readSettings(ctx context.Context, q Queryer, tenant int) (smtpSettings, error) {
	var cfg smtpSettings
	rows, err := q.QueryContext(ctx, `SELECT COALESCE(smtp_server,''),COALESCE(smtp_port,0),COALESCE(smtp_user,''),COALESCE(smtp_password,''),COALESCE(smtp_auth,'LOGIN'),COALESCE(message_from,''),COALESCE(smtp_encryption_type,'none'),tenant_settings IS NOT NULL
 FROM settings WHERE tenant_settings=$1 OR tenant_settings IS NULL ORDER BY tenant_settings NULLS LAST LIMIT 2`, tenant)
	if err != nil {
		return cfg, err
	}
	defer rows.Close()
	if !rows.Next() {
		return cfg, ErrConfiguration
	}
	var specific bool
	if err = rows.Scan(&cfg.host, &cfg.port, &cfg.username, &cfg.password, &cfg.auth, &cfg.from, &cfg.encryption, &specific); err != nil {
		return cfg, err
	}
	if !specific && rows.Next() {
		return cfg, ErrConfiguration
	} // Ambiguous global configuration.
	return cfg, rows.Err()
}

// Existing SMTP passwords use hex(nonce || AES-GCM ciphertext) without a marker.
// Authenticate plausible encrypted values instead of silently using a corrupt
// ciphertext as a password. Short/plain legacy values remain compatible.
func smtpPassword(value, key string) (string, error) {
	data, err := hex.DecodeString(value)
	if err != nil || len(data) < 12+16 {
		return value, nil
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", ErrConfiguration
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrConfiguration
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return "", ErrConfiguration
	}
	return string(plain), nil
}

func sendSMTP(parent context.Context, cfg smtpSettings, m Message, roots *x509.CertPool) error {
	if cfg.host == "" || strings.ContainsAny(cfg.host, "/\r\n\t ") || cfg.port < 1 || cfg.port > 65535 {
		return ErrConfiguration
	}
	from, err := mail.ParseAddress(cfg.from)
	if err != nil || strings.ContainsAny(cfg.from, "\r\n") {
		return ErrConfiguration
	}
	to, err := mail.ParseAddress(m.To)
	if err != nil || to.Address != m.To || strings.ContainsAny(m.To, "\r\n") {
		return ErrConfiguration
	}
	if cfg.encryption != "none" && cfg.encryption != "smtps" && cfg.encryption != "starttls" {
		return ErrConfiguration
	}
	if cfg.auth != "NOAUTH" && cfg.auth != "PLAIN" && cfg.auth != "LOGIN" && cfg.auth != "XOAUTH2" && cfg.auth != "SCRAM-SHA-256" {
		return ErrConfiguration
	}
	if cfg.username == "" && cfg.password == "" {
		cfg.auth = "NOAUTH"
	}
	if cfg.auth != "NOAUTH" && (cfg.username == "" || cfg.password == "" || cfg.encryption == "none") {
		return ErrConfiguration
	}
	msg := gomail.NewMsg()
	if err = msg.From(cfg.from); err != nil {
		return ErrConfiguration
	}
	if err = msg.To(to.Address); err != nil {
		return ErrConfiguration
	}
	msg.Subject(m.Subject)
	msg.SetMessageIDWithValue(m.ID + "@openuem.invalid")
	msg.SetDateWithValue(m.CreatedAt)
	msg.SetBodyString(gomail.TypeTextPlain, m.Text)
	if m.HTML != "" {
		msg.AddAlternativeString(gomail.TypeTextHTML, m.HTML)
	}
	var body bytes.Buffer
	if _, err = msg.WriteTo(&body); err != nil {
		return ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(cfg.host, strconv.Itoa(cfg.port)))
	if err != nil {
		return ErrDelivery
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return ErrDelivery
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	tlsConfig := &tls.Config{ServerName: cfg.host, RootCAs: roots, MinVersion: tls.VersionTLS12}
	var transport net.Conn = conn
	if cfg.encryption == "smtps" {
		secure := tls.Client(conn, tlsConfig)
		if err = secure.HandshakeContext(ctx); err != nil {
			return ErrDelivery
		}
		transport = secure
	}
	client, err := smtp.NewClient(transport, cfg.host)
	if err != nil {
		return ErrDelivery
	}
	defer client.Close()
	if cfg.encryption == "starttls" {
		if err = client.StartTLS(tlsConfig); err != nil {
			return ErrDelivery
		}
	}
	var auth smtp.Auth
	switch cfg.auth {
	case "PLAIN":
		auth = smtp.PlainAuth("", cfg.username, cfg.password, cfg.host, false)
	case "LOGIN":
		auth = smtp.LoginAuth(cfg.username, cfg.password, cfg.host, false)
	case "XOAUTH2":
		auth = smtp.XOAuth2Auth(cfg.username, cfg.password)
	case "SCRAM-SHA-256":
		auth = smtp.ScramSHA256Auth(cfg.username, cfg.password)
	}
	if auth != nil {
		if err = client.Auth(&boundedAuth{Auth: auth, ctx: ctx}); err != nil {
			return ErrDelivery
		}
	}
	if err = client.Mail("<" + from.Address + ">"); err != nil {
		return ErrDelivery
	}
	if err = client.Rcpt("<" + to.Address + ">"); err != nil {
		return ErrDelivery
	}
	w, err := client.Data()
	if err != nil {
		return ErrDelivery
	}
	if _, err = w.Write(body.Bytes()); err != nil {
		return ErrDelivery
	}
	if err = w.Close(); err != nil {
		return ErrDelivery
	}
	// DATA's final 250 response records SMTP acceptance. A later QUIT failure
	// must not resend an already accepted message. Inbox delivery is not proven.
	return nil
}

// Bound server-controlled authentication work as well as network I/O. In
// particular, the library otherwise accepts an unbounded SCRAM iteration count.
type boundedAuth struct {
	smtp.Auth
	ctx   context.Context
	steps int
}

func (a *boundedAuth) Next(challenge []byte, more bool) ([]byte, error) {
	a.steps++
	if a.ctx.Err() != nil || a.steps > 8 || len(challenge) > 8192 {
		return nil, ErrDelivery
	}
	if strings.HasPrefix(string(challenge), "r=") {
		parts := strings.Split(string(challenge), ",")
		if len(parts) != 3 || !strings.HasPrefix(parts[2], "i=") {
			return nil, ErrDelivery
		}
		iterations, err := strconv.Atoi(strings.TrimPrefix(parts[2], "i="))
		if err != nil || iterations < 1 || iterations > 100000 {
			return nil, ErrDelivery
		}
	}
	return a.Auth.Next(challenge, more)
}
