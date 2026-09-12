package apple

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
)

func TestVendorRequestPersistenceAndTrustChanges(t *testing.T) {
	base := testStore(t)
	f := newVendorFixture(t)
	s, err := NewStoreWithVendor(base.db, "integration-test-master-key-32-bytes-minimum", f.trust)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := newTestPushRequest(t, s, 1)
	f.csr, err = s.PushRequestCSR(ctx, 1, r.ID, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	encoded := f.envelope(t)
	if err := base.AttachVendorRequest(ctx, 1, r.ID, encoded, "test-admin"); !errors.Is(err, ErrVendorNotConfigured) {
		t.Fatal("unconfigured vendor accepted", err)
	}
	if err := s.AttachVendorRequest(ctx, 2, r.ID, encoded, "test-admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign organization attached vendor response", err)
	}
	other := newTestPushRequest(t, s, 1)
	if err := s.AttachVendorRequest(ctx, 1, other.ID, encoded, "test-admin"); !errors.Is(err, ErrVendorRequest) {
		t.Fatal("vendor response selected another CSR", err)
	}
	if err := s.AttachVendorRequest(ctx, 1, r.ID, encoded, "test-admin"); err != nil {
		t.Fatal(err)
	}
	saved, err := s.VendorPortalRequest(ctx, 1, r.ID, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	verified, err := f.trust.VerifyPortalRequest(f.csr, encoded, f.now)
	if err != nil || !bytes.Equal(saved, verified.Encoded) {
		t.Fatal("stored download changed signed request", err)
	}
	requests, err := s.PushRequests(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, request := range requests {
		if request.ID == r.ID {
			found = true
			if !request.VendorAvailable || !request.HasVendorRequest || request.VendorFingerprint != verified.Fingerprint {
				t.Fatal("missing verified metadata")
			}
		}
	}
	if !found {
		t.Fatal("request absent")
	}
	if _, err := s.VendorPortalRequest(ctx, 2, r.ID, "test-admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign organization downloaded signed response", err)
	}
	if _, err := s.db.Exec(`UPDATE mdm_apple_push_requests SET vendor_request=$1 WHERE id=$2`, []byte("tampered"), r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VendorPortalRequest(ctx, 1, r.ID, "test-admin"); !errors.Is(err, ErrVendorRequest) {
		t.Fatal("download skipped signature verification", err)
	}
	if _, err := s.db.Exec(`UPDATE mdm_apple_push_requests SET vendor_request=$1 WHERE id=$2`, saved, r.ID); err != nil {
		t.Fatal(err)
	}
	unapproved := &VendorTrust{root: f.trust.root, pins: map[string]struct{}{digest(f.chain[1].Raw): {}}}
	restarted, err := NewStoreWithVendor(base.db, "integration-test-master-key-32-bytes-minimum", unapproved)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.VendorPortalRequest(ctx, 1, r.ID, "test-admin"); !errors.Is(err, ErrVendorRequest) {
		t.Fatal("removed operator pin remained authorized", err)
	}
	requests, err = restarted.PushRequests(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range requests {
		if request.ID == r.ID && request.VendorAvailable {
			t.Fatal("removed signer advertised as available")
		}
	}
	if err := s.RevokePushRequest(ctx, 1, r.ID, "test-admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VendorPortalRequest(ctx, 1, r.ID, "test-admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("revoked request downloaded", err)
	}
	if err := s.AttachVendorRequest(ctx, 1, r.ID, encoded, "test-admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("revoked request replaced", err)
	}
	var keyRemoved bool
	if err := s.db.QueryRow(`SELECT encrypted_key IS NULL FROM mdm_apple_push_requests WHERE id=$1`, r.ID).Scan(&keyRemoved); err != nil || !keyRemoved {
		t.Fatal("vendor attachment prevented key revocation", err)
	}
}

func TestVendorRequestAuditRollbackAndConcurrentRevocation(t *testing.T) {
	base := testStore(t)
	f := newVendorFixture(t)
	s, err := NewStoreWithVendor(base.db, "integration-test-master-key-32-bytes-minimum", f.trust)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := newTestPushRequest(t, s, 1)
	f.csr, err = s.PushRequestCSR(ctx, 1, r.ID, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	encoded := f.envelope(t)
	if _, err := s.db.Exec(`CREATE FUNCTION reject_vendor_attach() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.push_request.vendor_attach' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_vendor_attach BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_vendor_attach()`); err != nil {
		t.Fatal(err)
	}
	if err := s.AttachVendorRequest(ctx, 1, r.ID, encoded, "test-admin"); err == nil {
		t.Fatal("audit failure ignored")
	}
	var unchanged bool
	if err := s.db.QueryRow(`SELECT vendor_request IS NULL AND vendor_fingerprint='' AND vendor_expires_at IS NULL AND encrypted_key IS NOT NULL FROM mdm_apple_push_requests WHERE id=$1`, r.ID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("failed audit partially attached vendor response", err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_vendor_attach ON mdm_apple_audit`); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var attachErr, revokeErr error
	var wg sync.WaitGroup
	wg.Go(func() { <-start; attachErr = s.AttachVendorRequest(ctx, 1, r.ID, encoded, "test-admin") })
	wg.Go(func() { <-start; revokeErr = s.RevokePushRequest(ctx, 1, r.ID, "test-admin") })
	close(start)
	wg.Wait()
	if revokeErr != nil {
		t.Fatal(revokeErr)
	}
	if attachErr != nil && !errors.Is(attachErr, ErrConflict) {
		t.Fatal(attachErr)
	}
	if _, err := s.VendorPortalRequest(ctx, 1, r.ID, "test-admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("concurrent attachment revived request", err)
	}
}
