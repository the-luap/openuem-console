package webserver

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestWindowsCertificateEmailSeparatesIssuanceExpiryAndPending(t *testing.T) {
	now := time.Now().UTC()
	for _, kind := range []string{"device_expiry", "issuer_expiry", "issuer_issuance"} {
		m := windows.CertificateExpiryMessage{ID: uuid.NewString(), Recipient: "admin@example.test", Kind: kind, DeviceID: "<script>synthetic</script>", Fingerprint: strings.Repeat("ab", 32), Scope: access.Scope{TenantID: 42, SiteID: 11}, CreatedAt: now, AssessedAt: now, Deadline: now, Stage: 0, PendingReplacement: kind == "device_expiry"}
		got := windowsCertificateExpiryEmail(m)
		if got.ID != m.ID || got.To != m.Recipient || strings.Contains(got.HTML, "<script>synthetic</script>") || !strings.Contains(got.Text, "SMTP acceptance does not confirm delivery") || !strings.Contains(got.Text, "does not schedule or perform a renewal") {
			t.Fatal("certificate email lost identity, escaping or delivery boundary")
		}
		if kind == "device_expiry" && (!strings.Contains(got.HTML, "&lt;script&gt;synthetic&lt;/script&gt;") || !strings.Contains(got.Text, "replacement is awaiting confirmation")) {
			t.Fatal("pending replacement/escaping missing")
		}
		if kind == "issuer_issuance" && (!strings.Contains(got.Subject, "issuance is unavailable") || !strings.Contains(got.Text, "earlier than CA expiry")) {
			t.Fatal("issuance deadline reported as CA expiry")
		}
	}
}

func TestWindowsCertificateSenderDeliversScopedMessageToLoopbackSMTP(t *testing.T) {
	db := windowsStartupTestDatabase(t)
	if _, err := db.Exec(`CREATE TABLE settings(smtp_server TEXT,smtp_port INTEGER,smtp_user TEXT,smtp_password TEXT,smtp_auth TEXT,message_from TEXT,smtp_encryption_type TEXT,tenant_settings BIGINT)`); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := db.Exec(`INSERT INTO settings(smtp_server,smtp_port,smtp_auth,message_from,smtp_encryption_type,tenant_settings) VALUES('127.0.0.1',$1,'NOAUTH','from@example.test','none',1)`, listener.Addr().(*net.TCPAddr).Port); err != nil {
		t.Fatal(err)
	}
	type received struct {
		data      string
		recipient string
		err       error
	}
	message := make(chan received, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			message <- received{err: err}
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		peer := textproto.NewConn(conn)
		peer.PrintfLine("220 synthetic SMTP ready")
		rcpt := ""
		for {
			line, err := peer.ReadLine()
			if err != nil {
				message <- received{err: err}
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO "):
				peer.PrintfLine("250 synthetic.example.test")
			case strings.HasPrefix(line, "MAIL FROM:"):
				peer.PrintfLine("250 sender accepted")
			case strings.HasPrefix(line, "RCPT TO:"):
				rcpt = line
				peer.PrintfLine("250 recipient accepted")
			case line == "DATA":
				peer.PrintfLine("354 send message")
				data, err := peer.ReadDotBytes()
				if err != nil {
					message <- received{err: err}
					return
				}
				peer.PrintfLine("250 accepted")
				message <- received{data: string(data), recipient: rcpt}
				return
			default:
				peer.PrintfLine("500 unexpected command")
			}
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	m := windows.CertificateExpiryMessage{ID: uuid.NewString(), Recipient: "admin@example.test", Kind: "device_expiry", DeviceID: uuid.NewString(), Fingerprint: strings.Repeat("ab", 32), Scope: access.Scope{TenantID: 1, SiteID: 11}, Stage: 1, CreatedAt: time.Now(), AssessedAt: time.Now(), Deadline: time.Now().Add(time.Hour), PendingReplacement: true}
	if err := windowsCertificateSender("")(ctx, tx, m); err != nil {
		t.Fatal("synthetic SMTP DATA acceptance failed", err)
	}
	var receivedMessage received
	select {
	case receivedMessage = <-message:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if receivedMessage.err != nil || receivedMessage.recipient != "RCPT TO:<admin@example.test>" {
		t.Fatal("wrong SMTP envelope", receivedMessage.err)
	}
	parsed, err := mail.ReadMessage(strings.NewReader(receivedMessage.data))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Get("Message-ID") != "<"+m.ID+"@openuem.invalid>" || !strings.Contains(parsed.Header.Get("Subject"), "Windows device certificate expires within 1 day") {
		t.Fatal("SMTP headers lost stable identity or purpose")
	}
	_, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	parts := multipart.NewReader(parsed.Body, params["boundary"])
	count := 0
	for {
		part, err := parts.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var body io.Reader = part
		if strings.EqualFold(part.Header.Get("Content-Transfer-Encoding"), "quoted-printable") {
			body = quotedprintable.NewReader(part)
		}
		data, err := io.ReadAll(body)
		if err != nil {
			t.Fatal(err)
		}
		part.Close()
		for _, want := range []string{m.DeviceID, m.Fingerprint, "replacement is awaiting confirmation", "organization 1"} {
			if !strings.Contains(string(data), want) {
				t.Fatal("SMTP body lost scoped certificate information", want)
			}
		}
		count++
	}
	if count != 2 {
		t.Fatal("SMTP message omitted plain text or HTML")
	}
}

type windowsMaintenanceFixture struct{ updates, reminders chan struct{} }

func (f windowsMaintenanceFixture) RunUpdateSchedules(ctx context.Context, _ *slog.Logger) {
	close(f.updates)
	<-ctx.Done()
}
func (f windowsMaintenanceFixture) RunCertificateReminders(ctx context.Context, _ *slog.Logger, _ windows.CertificateReminderSender) {
	close(f.reminders)
	<-ctx.Done()
}

func TestWindowsMaintenanceStartsAndJoinsBothWorkers(t *testing.T) {
	f := windowsMaintenanceFixture{make(chan struct{}), make(chan struct{})}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWindowsMaintenance(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), f, nil)
		close(done)
	}()
	for _, started := range []chan struct{}{f.updates, f.reminders} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("Windows maintenance workers did not run together")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Windows maintenance failed to join workers")
	}
}

func TestWindowsCertificateSenderCancelsStalledLoopbackSMTP(t *testing.T) {
	db := windowsStartupTestDatabase(t)
	if _, err := db.Exec(`CREATE TABLE settings(smtp_server TEXT,smtp_port INTEGER,smtp_user TEXT,smtp_password TEXT,smtp_auth TEXT,message_from TEXT,smtp_encryption_type TEXT,tenant_settings BIGINT)`); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := db.Exec(`INSERT INTO settings(smtp_server,smtp_port,smtp_auth,message_from,smtp_encryption_type,tenant_settings) VALUES('127.0.0.1',$1,'NOAUTH','from@example.test','none',1)`, listener.Addr().(*net.TCPAddr).Port); err != nil {
		t.Fatal(err)
	}
	entered, closed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(closed)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		close(entered)
		io.Copy(io.Discard, conn)
	}()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	done := make(chan error, 1)
	go func() {
		done <- windowsCertificateSender("")(ctx, tx, windows.CertificateExpiryMessage{ID: uuid.NewString(), Recipient: "admin@example.test", Kind: "issuer_expiry", Scope: access.Scope{TenantID: 1}, Stage: 1, CreatedAt: time.Now(), AssessedAt: time.Now(), Deadline: time.Now().Add(time.Hour)})
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("Windows reminder did not reach loopback SMTP")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled SMTP reported acceptance")
		}
	case <-time.After(time.Second):
		t.Fatal("SMTP did not honor shutdown")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("SMTP connection survived cancellation")
	}
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		t.Fatal(err)
	}
}
