package apple

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestPushRequest(t *testing.T, s *Store, tenant int) *PushRequest {
	t.Helper()
	r, err := s.CreatePushRequest(context.Background(), tenant, "Request organization", "https://mdm.example.test/", "mdm-owner@example.test", "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// This is a synthetic issuer, not Apple acceptance or a vendor signing fixture.
// It has only the public CSR; the request private key remains in the store.
func issueTestPushCertificate(t *testing.T, s *Store, tenant int, id, topic string, expires time.Time) []byte {
	t.Helper()
	csr, err := s.PushRequestCSR(context.Background(), tenant, id, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(csr)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		t.Fatal("not a public PKCS#10 request")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil {
		t.Fatal("invalid CSR signature", err)
	}
	if request.Subject.Organization[0] != "Request organization" || !strings.Contains(request.Subject.CommonName, id) {
		t.Fatal("CSR lost request association")
	}
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic push certificate", ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: topic}}}, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, request.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestPushRequestCertificateLifecycle(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a := newTestPushRequest(t, s, 1)
	b := newTestPushRequest(t, s, 1)
	certificate := issueTestPushCertificate(t, s, 1, a.ID, "com.apple.mgmt.requests", time.Now().Add(365*24*time.Hour))
	for _, bad := range [][]byte{
		append(append([]byte{}, certificate...), []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----")...),
		append([]byte("-----BEGIN CERTIFICATE-----\nmalformed\n"), certificate...),
		append([]byte("preamble\n"), certificate...),
		bytes.Repeat(certificate, 9),
	} {
		if err := s.ImportPushCertificate(ctx, 1, a.ID, bad, "test-admin"); err == nil {
			t.Fatal("non-certificate or excessive upload accepted")
		}
	}
	if _, err := s.SettingsMetadata(ctx, 1); !errors.Is(err, ErrNotFound) {
		t.Fatal("CSR creation configured device management", err)
	}
	if err := s.ImportPushCertificate(ctx, 1, b.ID, certificate, "test-admin"); err == nil {
		t.Fatal("certificate selected another request's key")
	}
	if err := s.ImportPushCertificate(ctx, 2, a.ID, certificate, "test-admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-organization import", err)
	}
	if _, err := s.PushRequestCSR(ctx, 2, a.ID, "test-admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-organization download", err)
	}
	if err := s.ImportPushCertificate(ctx, 1, a.ID, certificate, "test-admin"); err != nil {
		t.Fatal(err)
	}
	metadata, err := s.SettingsMetadata(ctx, 1)
	if err != nil || metadata.AppleAccount != "mdm-owner@example.test" || metadata.PublicURL != "https://mdm.example.test" {
		t.Fatal("missing administrative metadata", metadata, err)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil || bytes.Contains(encoded, []byte("mdm-owner")) || len(metadata.PushKey) != 0 || len(metadata.CAKey) != 0 || len(metadata.PushCertificate) != 0 {
		t.Fatal("metadata exposed credentials or public JSON exposed account", err)
	}
	for _, id := range []string{a.ID, b.ID} {
		var status string
		var removed bool
		if err := s.db.QueryRow(`SELECT status,encrypted_key IS NULL FROM mdm_apple_push_requests WHERE id=$1`, id).Scan(&status, &removed); err != nil || !removed {
			t.Fatal("consumed or superseded request retained key", err)
		}
		if id == a.ID && status != "imported" || id == b.ID && status != "superseded" {
			t.Fatal("wrong final state", status)
		}
		if err := s.ImportPushCertificate(ctx, 1, id, certificate, "test-admin"); !errors.Is(err, ErrConflict) {
			t.Fatal("consumed request accepted", err)
		}
	}
	old, err := s.Settings(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	renewal := newTestPushRequest(t, s, 1)
	if renewal.BaseRevision != 1 || renewal.ExpectedTopic != old.Topic {
		t.Fatal("renewal missing existing generation or topic")
	}
	for _, tc := range []struct {
		topic   string
		expires time.Time
	}{{"com.apple.mgmt.new-topic", time.Now().Add(time.Hour)}, {old.Topic, time.Now().Add(-time.Hour)}, {"", time.Now().Add(time.Hour)}} {
		bad := issueTestPushCertificate(t, s, 1, renewal.ID, tc.topic, tc.expires)
		if err := s.ImportPushCertificate(ctx, 1, renewal.ID, bad, "test-admin"); err == nil {
			t.Fatal("invalid renewal accepted")
		}
	}
	unchanged, _ := s.Settings(ctx, 1)
	if !bytes.Equal(old.PushCertificate, unchanged.PushCertificate) || !bytes.Equal(old.PushKey, unchanged.PushKey) {
		t.Fatal("failed import changed active credentials")
	}
	renewed := issueTestPushCertificate(t, s, 1, renewal.ID, old.Topic, time.Now().Add(366*24*time.Hour))
	if err := s.ImportPushCertificate(ctx, 1, renewal.ID, renewed, "test-admin"); err != nil {
		t.Fatal(err)
	}
	current, _ := s.Settings(ctx, 1)
	if !bytes.Equal(current.CACertificate, old.CACertificate) || !bytes.Equal(current.CAKey, old.CAKey) || bytes.Equal(current.PushKey, old.PushKey) {
		t.Fatal("renewal changed CA or reused old push key")
	}
}

func TestPushRequestEncryptedAssociationAndRollback(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	old := testSettings(t, s, 1)
	a := newTestPushRequest(t, s, 1)
	b := newTestPushRequest(t, s, 1)
	certificate := issueTestPushCertificate(t, s, 1, a.ID, old.Topic, time.Now().Add(time.Hour))
	var ciphertext []byte
	if err := s.db.QueryRow(`SELECT encrypted_key FROM mdm_apple_push_requests WHERE id=$1`, a.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("PRIVATE KEY")) {
		t.Fatal("plaintext key stored")
	}
	if _, err := s.secrets.open(ciphertext, secretPurpose(1, "push_request/"+b.ID, "key")); err == nil {
		t.Fatal("ciphertext not bound to request")
	}
	if _, err := s.secrets.open(ciphertext, secretPurpose(2, "push_request/"+a.ID, "key")); err == nil {
		t.Fatal("ciphertext not bound to organization")
	}
	if _, err := s.db.Exec(`UPDATE mdm_apple_push_requests SET encrypted_key=(SELECT encrypted_key FROM mdm_apple_push_requests WHERE id=$1) WHERE id=$2`, b.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ImportPushCertificate(ctx, 1, a.ID, certificate, "test-admin"); err == nil {
		t.Fatal("swapped ciphertext accepted")
	}
	if _, err := s.db.Exec(`UPDATE mdm_apple_push_requests SET encrypted_key=$1 WHERE id=$2`, ciphertext, a.ID); err != nil {
		t.Fatal(err)
	}
	// Fail the last audit insert, after settings and both request states change.
	if _, err := s.db.Exec(`CREATE FUNCTION reject_push_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.push_request.import' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_push_import BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_push_import()`); err != nil {
		t.Fatal(err)
	}
	if err := s.ImportPushCertificate(ctx, 1, a.ID, certificate, "test-admin"); err == nil {
		t.Fatal("audit failure ignored")
	}
	current, _ := s.Settings(ctx, 1)
	if !bytes.Equal(old.PushCertificate, current.PushCertificate) || !bytes.Equal(old.PushKey, current.PushKey) {
		t.Fatal("audit failure left replaced settings")
	}
	for _, id := range []string{a.ID, b.ID} {
		if _, err := s.PushRequestCSR(ctx, 1, id, "test-admin"); err != nil {
			t.Fatal("rollback consumed or superseded request", err)
		}
	}
}

func TestPushRequestConcurrentRenewalAndLegacyReplacement(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	old := testSettings(t, s, 1)
	a := newTestPushRequest(t, s, 1)
	b := newTestPushRequest(t, s, 1)
	certificates := [][]byte{issueTestPushCertificate(t, s, 1, a.ID, old.Topic, time.Now().Add(time.Hour)), issueTestPushCertificate(t, s, 1, b.ID, old.Topic, time.Now().Add(2*time.Hour))}
	start := make(chan struct{})
	results := make([]error, 2)
	var wg sync.WaitGroup
	for i, id := range []string{a.ID, b.ID} {
		wg.Go(func() { <-start; results[i] = s.ImportPushCertificate(ctx, 1, id, certificates[i], "test-admin") })
	}
	close(start)
	wg.Wait()
	winner := -1
	for i, err := range results {
		if err == nil {
			if winner != -1 {
				t.Fatal("both competing renewals succeeded")
			}
			winner = i
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if winner == -1 {
		t.Fatal("no renewal succeeded")
	}
	current, _ := s.Settings(ctx, 1)
	if !bytes.Equal(current.PushCertificate, certificates[winner]) {
		t.Fatal("wrong winner persisted")
	}
	r := newTestPushRequest(t, s, 1)
	if err := s.Configure(ctx, *current, "test-admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PushRequestCSR(ctx, 1, r.ID, "test-admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("legacy replacement left stale request", err)
	}
	metadata, _ := s.SettingsMetadata(ctx, 1)
	if metadata.AppleAccount != "mdm-owner@example.test" {
		t.Fatal("legacy replacement erased responsible account")
	}
}

func TestPushRequestRevocationExpiryAndLimits(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a := newTestPushRequest(t, s, 1)
	certificate := issueTestPushCertificate(t, s, 1, a.ID, "com.apple.mgmt.test", time.Now().Add(time.Hour))
	if err := s.RevokePushRequest(ctx, 2, a.ID, "test-admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-organization revoke", err)
	}
	if err := s.RevokePushRequest(ctx, 1, a.ID, "test-admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.ImportPushCertificate(ctx, 1, a.ID, certificate, "test-admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("revoked request imported", err)
	}
	b := newTestPushRequest(t, s, 1)
	if _, err := s.db.Exec(`UPDATE mdm_apple_push_requests SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PushRequestCSR(ctx, 1, b.ID, "test-admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("expired CSR exported", err)
	}
	if err := s.ImportPushCertificate(ctx, 1, b.ID, certificate, "test-admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("expired request imported", err)
	}
	if err := s.CleanupPushRequests(ctx); err != nil {
		t.Fatal(err)
	}
	var removed bool
	if err := s.db.QueryRow(`SELECT status='expired' AND encrypted_key IS NULL FROM mdm_apple_push_requests WHERE id=$1`, b.ID).Scan(&removed); err != nil || !removed {
		t.Fatal("expired key retained", err)
	}
	manual := newTestPushRequest(t, s, 1)
	if _, err := s.db.Exec(`UPDATE mdm_apple_push_requests SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, manual.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokePushRequest(ctx, 1, manual.ID, "test-admin"); err != nil {
		t.Fatal("cannot remove expired pending key without worker", err)
	}
	if err := s.db.QueryRow(`SELECT status='revoked' AND encrypted_key IS NULL FROM mdm_apple_push_requests WHERE id=$1`, manual.ID).Scan(&removed); err != nil || !removed {
		t.Fatal("manual expired key removal failed", err)
	}
	var ids []string
	for range 5 {
		ids = append(ids, newTestPushRequest(t, s, 1).ID)
	}
	if _, err := s.CreatePushRequest(ctx, 1, "Example", "https://mdm.example.test", "account", "test-admin"); err == nil {
		t.Fatal("pending limit ignored")
	}
	if err := s.RevokePushRequest(ctx, 1, ids[0], "test-admin"); err != nil {
		t.Fatal(err)
	}
	newTestPushRequest(t, s, 1)
	requests, err := s.PushRequests(ctx, 2)
	if err != nil || len(requests) != 0 {
		t.Fatal("history crossed organizations", err)
	}
}

func TestPushRequestCertificateOnlyParsing(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("private"), []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----"), bytes.Repeat([]byte("x"), (64<<10)+1)} {
		if err := certificateOnlyPEM(data); err == nil {
			t.Fatal("non-certificate accepted")
		}
	}
}
