package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestWindowsRenewalDetailsBindCertificatesScopeAndResolution(t *testing.T) {
	f := renewalTestStore(t)
	if _, err := f.renew(f.request(t, f.key)); err != nil {
		t.Fatal(err)
	}
	r := f.history(t)[0]
	ctx := context.Background()
	read := func() *CertificateRenewalDetail {
		t.Helper()
		d, err := f.store.CertificateRenewalDetails(ctx, "admin", f.identity.Scope, f.identity.DeviceID, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := read()
	if d.Renewal.ID != r.ID || d.Source.ID != f.identity.CertificateID || d.Source.FingerprintSHA256 != f.identity.FingerprintSHA256 || d.Replacement.ID != r.RenewedCertificateID || d.Replacement.AuthorityID != d.Source.AuthorityID || d.Replacement.FingerprintSHA256 == d.Source.FingerprintSHA256 || !d.Source.ExpiresAt.Equal(f.certificate.NotAfter) || d.Replacement.RevokedAt != nil || d.Source.RevokedAt != nil || d.Resolution != "" {
		t.Fatal("renewal detail lost certificate or phase binding")
	}
	for _, actor := range []string{"operator", "viewer", "foreign", "missing"} {
		if got, err := f.store.CertificateRenewalDetails(ctx, actor, f.identity.Scope, f.identity.DeviceID, r.ID); err == nil || got != nil {
			t.Fatal("protected detail disclosed without certificate administration")
		}
	}
	for _, scope := range []access.Scope{{TenantID: 1, SiteID: 12}, {TenantID: 2, SiteID: 21}, {TenantID: 1}} {
		if got, err := f.store.CertificateRenewalDetails(ctx, "admin", scope, f.identity.DeviceID, r.ID); err == nil || got != nil {
			t.Fatal("protected detail crossed device scope")
		}
	}
	if got, err := f.store.CertificateRenewalDetails(ctx, "admin", f.identity.Scope, uuid.NewString(), r.ID); !errors.Is(err, ErrNotFound) || got != nil {
		t.Fatal("renewal reassigned to another device", err)
	}
	if got, err := f.store.CertificateRenewalDetails(ctx, "admin", f.identity.Scope, f.identity.DeviceID, uuid.NewString()); !errors.Is(err, ErrNotFound) || got != nil {
		t.Fatal("missing renewal disclosed", err)
	}
	if got, err := f.store.CertificateRenewalDetails(ctx, "admin", f.identity.Scope, f.identity.DeviceID, "invalid"); !errors.Is(err, ErrConsoleInput) || got != nil {
		t.Fatal("invalid identifier accepted", err)
	}
	resolution := "Reviewed <script>synthetic replacement</script>"
	if err := f.store.CancelCertificateRenewal(ctx, "admin", f.identity.Scope, f.identity.DeviceID, r.ID, 1, resolution); err != nil {
		t.Fatal(err)
	}
	d = read()
	if d.Renewal.Phase != "canceled" || d.Renewal.Revision != 2 || d.Resolution != resolution || d.Source.RevokedAt != nil || d.Replacement.RevokedAt == nil || !d.Replacement.RevokedAt.Equal(*d.Renewal.CompletedAt) {
		t.Fatal("cancellation detail changed lifecycle meaning")
	}
	for _, value := range []any{d, d.Source, d.Replacement} {
		encoded, err := json.Marshal(value)
		if err != nil || string(encoded) != "{}" {
			t.Fatal("generic JSON disclosed protected detail", err)
		}
		for _, secret := range []string{resolution, r.ID, d.Replacement.FingerprintSHA256} {
			if strings.Contains(fmt.Sprintf("%+v %#v", value, value), secret) {
				t.Fatal("formatted detail disclosed metadata")
			}
		}
	}
	if err := f.store.RevokeDevice(ctx, "admin", f.identity.Scope, f.identity.DeviceID); err != nil {
		t.Fatal(err)
	}
	if read().Resolution != resolution {
		t.Fatal("device revocation erased history")
	}
	if _, err := f.store.db.Exec(`CREATE FUNCTION reject_renewal_detail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic detail audit failure'; END; $$; CREATE TRIGGER reject_renewal_detail_audit BEFORE INSERT ON mdm_windows_renewal_audit FOR EACH ROW EXECUTE FUNCTION reject_renewal_detail_audit()`); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.CertificateRenewalDetails(ctx, "admin", f.identity.Scope, f.identity.DeviceID, r.ID); err == nil || got != nil {
		t.Fatal("failed detail audit disclosed resolution")
	}
	if _, err := f.store.db.Exec(`DROP TRIGGER reject_renewal_detail_audit ON mdm_windows_renewal_audit; ALTER TABLE mdm_windows_device_certificates DISABLE TRIGGER mdm_windows_device_certificate`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE mdm_windows_device_certificates SET revoked_at=revoked_at+INTERVAL '1 second' WHERE id=$1`, r.RenewedCertificateID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`ALTER TABLE mdm_windows_device_certificates ENABLE TRIGGER mdm_windows_device_certificate`); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.CertificateRenewalDetails(ctx, "admin", f.identity.Scope, f.identity.DeviceID, r.ID); !errors.Is(err, ErrAuthoritySecret) || got != nil {
		t.Fatal("detail accepted revocation inconsistent with sealed cancellation", err)
	}
}

func TestWindowsRenewalConfirmedDetailPreservesConfirmationEvidence(t *testing.T) {
	f := renewalTestStore(t)
	first, err := f.process(f.initial(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.renew(f.request(t, f.key)); err != nil {
		t.Fatal(err)
	}
	r := f.history(t)[0]
	candidate := f.candidate(t, r.RenewedCertificateID, f.key)
	if _, err := candidate.process(syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))); err != nil {
		t.Fatal(err)
	}
	d, err := f.store.CertificateRenewalDetails(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, r.ID)
	if err != nil || d.Renewal.Phase != "confirmed" || d.Renewal.ConfirmedMessageID != 2 || d.Renewal.ConfirmedSessionID == "" || d.Source.RevokedAt == nil || !d.Source.RevokedAt.Equal(*d.Renewal.CompletedAt) || d.Replacement.RevokedAt != nil {
		t.Fatal("confirmed detail lost authenticated packet evidence", err)
	}
}
