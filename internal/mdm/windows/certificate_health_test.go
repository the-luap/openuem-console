package windows

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func certificateHealthTestOptions() CertificateHealthOptions {
	return CertificateHealthOptions{Filter: "all", WithinDays: 30, Limit: 25}
}

func TestWindowsCertificateHealthBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	before, expires, opens := now.Add(-time.Hour), now.Add(30*24*time.Hour), now.Add(20*24*time.Hour)
	for _, test := range []struct {
		name             string
		at               time.Time
		revoked, retired *time.Time
		want             string
	}{
		{"outside warning", now.Add(-time.Nanosecond), nil, nil, "valid"},
		{"warning boundary", now, nil, nil, "expires_soon"},
		{"renewal boundary", opens, nil, nil, "renewal_due"},
		{"expiry boundary", expires, nil, nil, "expired"},
		{"not yet valid", before.Add(-time.Nanosecond), nil, nil, "not_yet_valid"},
		{"revoked", expires, &now, nil, "revoked"},
		{"retired", expires, &now, &now, "retired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := currentCertificateHealth(test.at, before, expires, opens, test.revoked, test.retired, 30); got != test.want {
				t.Fatalf("got %s, want %s", got, test.want)
			}
		})
	}
	a := CertificateAuthorityHealth{NotBefore: before, CreatedAt: before, ExpiresAt: expires.Add(100 * 24 * time.Hour), IssuanceEndsAt: expires}
	for _, test := range []struct {
		at   time.Time
		want string
	}{
		{now.Add(-time.Nanosecond), "available"}, {now, "issuance_ending"}, {expires, "issuance_unavailable"}, {a.ExpiresAt, "expired"}, {before.Add(-time.Nanosecond), "not_yet_valid"},
	} {
		if got := authorityHealthState(test.at, a, 30); got != test.want {
			t.Fatalf("issuer: got %s, want %s", got, test.want)
		}
	}
	a.CreatedAt = now.Add(time.Hour)
	if authorityHealthState(now, a, 30) != "not_yet_valid" {
		t.Fatal("future issuer creation appeared ready")
	}
}

func TestWindowsCertificateHealthScopeFiltersAndAudit(t *testing.T) {
	f := syncMLTestStore(t)
	s, scope, ctx := f.store, f.identity.Scope, t.Context()
	options := certificateHealthTestOptions()
	read := func(actor string, scope access.Scope, options CertificateHealthOptions) *CertificateHealthReport {
		t.Helper()
		r, err := s.CertificateHealth(ctx, actor, scope, options)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := read("admin", scope, options)
	if r.Scope != scope || r.AssessedAt.IsZero() || r.Authority == nil || r.Authority.State != "available" || len(r.Devices) != 1 {
		t.Fatal("missing scoped health")
	}
	d := r.Devices[0]
	if d.Current.ID != f.identity.CertificateID || d.Current.FingerprintSHA256 != f.identity.FingerprintSHA256 || d.CurrentState != "valid" || d.Pending != nil || d.ConfirmedRenewalID != "" || !d.Current.ExpiresAt.Equal(f.certificate.NotAfter) || !d.RenewalOpensAt.Equal(f.certificate.NotAfter.Add(-14*24*time.Hour)) {
		t.Fatal("current identity health changed")
	}
	if !r.Authority.IssuanceEndsAt.Equal(r.Authority.ExpiresAt.Add(-90*24*time.Hour - 5*time.Minute)) {
		t.Fatal("issuer warning omitted full leaf lifetime margin")
	}
	for _, actor := range []string{"operator", "viewer", "foreign", "missing", ""} {
		if got, err := s.CertificateHealth(ctx, actor, scope, options); err == nil || got != nil {
			t.Fatal("certificate health escaped administration scope")
		}
	}
	if err := s.permissions.ReplaceGrants(ctx, "admin", "second", 1, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}); err != nil {
		t.Fatal(err)
	}
	if len(read("second", scope, options).Devices) != 1 {
		t.Fatal("organization administrator lost device health")
	}
	if got, err := s.CertificateHealth(ctx, "operator", access.Scope{TenantID: 1}, options); !errors.Is(err, access.ErrDenied) || got != nil {
		t.Fatal("site certificate grant escaped into all sites", err)
	}
	if len(read("admin", access.Scope{TenantID: 1}, options).Devices) != 1 {
		t.Fatal("organization health omitted device")
	}
	if got := read("admin", access.Scope{TenantID: 1, SiteID: 12}, options); len(got.Devices) != 0 || got.Authority == nil {
		t.Fatal("sibling scope included device")
	}
	if got := read("admin", access.Scope{TenantID: 2}, options); len(got.Devices) != 0 || got.Authority != nil {
		t.Fatal("unconfigured organization inherited issuer")
	}
	for _, filter := range []string{"attention", "pending", "renewal_due", "expires_soon", "expired", "retired"} {
		o := options
		o.Filter = filter
		if len(read("admin", scope, o).Devices) != 0 {
			t.Fatal("healthy device matched", filter)
		}
	}
	for _, search := range []string{strings.ToUpper(d.Device.Name), strings.ToUpper(d.Device.ID)} {
		o := options
		o.Search = search
		if len(read("admin", scope, o).Devices) != 1 {
			t.Fatal("literal case-insensitive search failed")
		}
	}
	o := options
	o.Search = "%"
	if len(read("admin", scope, o).Devices) != 0 {
		t.Fatal("search interpreted wildcard")
	}
	o = options
	o.Offset = 1
	if len(read("admin", scope, o).Devices) != 0 {
		t.Fatal("page offset repeated device")
	}
	o = options
	o.WithinDays = 90
	o.Filter = "expires_soon"
	if got := read("admin", scope, o); len(got.Devices) != 1 || got.Devices[0].CurrentState != "expires_soon" {
		t.Fatal("warning horizon ignored")
	}
	for _, mutate := range []func(*CertificateHealthOptions){
		func(o *CertificateHealthOptions) { o.WithinDays = 0 }, func(o *CertificateHealthOptions) { o.WithinDays = 366 }, func(o *CertificateHealthOptions) { o.Filter = "unknown" }, func(o *CertificateHealthOptions) { o.Search = "bad\nsearch" }, func(o *CertificateHealthOptions) { o.Search = string([]byte{255}) }, func(o *CertificateHealthOptions) { o.Search = strings.Repeat("x", 129) }, func(o *CertificateHealthOptions) { o.Offset = -1 }, func(o *CertificateHealthOptions) { o.Offset = 100001 }, func(o *CertificateHealthOptions) { o.Limit = 0 }, func(o *CertificateHealthOptions) { o.Limit = 101 },
	} {
		o := options
		mutate(&o)
		if got, err := s.CertificateHealth(ctx, "admin", scope, o); !errors.Is(err, ErrConsoleInput) || got != nil {
			t.Fatal("invalid health filter admitted", err)
		}
	}
	for _, value := range []any{*r, *r.Authority, d} {
		encoded, err := json.Marshal(value)
		if err != nil || string(encoded) != "{}" {
			t.Fatal("generic JSON disclosed certificate health")
		}
		x, err := xml.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{d.Device.ID, d.Current.FingerprintSHA256, r.Authority.FingerprintSHA256} {
			if strings.Contains(fmt.Sprintf("%+v %#v %s", value, value, x), private) {
				t.Fatal("generic formatting disclosed protected health")
			}
		}
	}
	if _, err := s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=11`); err != nil {
		t.Fatal(err)
	}
	if len(read("admin", access.Scope{TenantID: 1}, options).Devices) != 0 {
		t.Fatal("moved site remained in former organization health")
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_windows_console_audit WHERE action='certificate_health.read' AND tenant_id=1 AND site_id=0 AND resource_id IS NULL`).Scan(&count); err != nil || count != 2 {
		t.Fatal("organization health audit missing", count, err)
	}
}

func TestWindowsCertificateHealthPendingConfirmedCanceledAndRetired(t *testing.T) {
	f := renewalTestStore(t)
	options := certificateHealthTestOptions()
	read := func(filter string) *CertificateHealthReport {
		t.Helper()
		o := options
		o.Filter = filter
		r, err := f.store.CertificateHealth(t.Context(), "admin", f.identity.Scope, o)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, filter := range []string{"renewal_due", "expires_soon", "attention"} {
		if r := read(filter); len(r.Devices) != 1 || r.Devices[0].CurrentState != "renewal_due" {
			t.Fatal("renewal admission window omitted", filter)
		}
	}
	if _, err := f.renew(f.request(t, f.key)); err != nil {
		t.Fatal(err)
	}
	r := f.history(t)[0]
	health := read("pending").Devices[0]
	if health.Current.ID != r.SourceCertificateID || health.Pending == nil || health.Pending.ID != r.ID || health.Replacement == nil || health.Replacement.ID != r.RenewedCertificateID || health.ReplacementState != "valid" {
		t.Fatal("pending candidate replaced current identity")
	}
	if err := f.store.CancelCertificateRenewal(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, r.ID, r.Revision, "Synthetic health check"); err != nil {
		t.Fatal(err)
	}
	if len(read("pending").Devices) != 0 || read("all").Devices[0].Current.ID != f.identity.CertificateID {
		t.Fatal("canceled candidate remained pending or current")
	}
	first, err := f.process(f.initial(t))
	if err != nil {
		t.Fatal(err)
	}
	key := renewalTestKey(t)
	if _, err := f.renew(f.request(t, key)); err != nil {
		t.Fatal(err)
	}
	r = f.history(t)[0]
	candidate := f.candidate(t, r.RenewedCertificateID, key)
	if _, err := candidate.process(syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))); err != nil {
		t.Fatal(err)
	}
	health = read("all").Devices[0]
	if health.Current.ID != r.RenewedCertificateID || health.ConfirmedRenewalID != r.ID || health.Current.RevokedAt != nil || health.Pending != nil || health.Replacement != nil || len(read("pending").Devices) != 0 {
		t.Fatal("confirmed handoff did not become sole current identity")
	}
	if err := f.store.RevokeDevice(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID); err != nil {
		t.Fatal(err)
	}
	health = read("retired").Devices[0]
	if health.CurrentState != "retired" || health.Current.ID != r.RenewedCertificateID || health.Device.RevokedAt == nil || len(read("attention").Devices) != 0 {
		t.Fatal("retirement lost confirmed identity or became active warning")
	}
}

func TestWindowsCertificateHealthExpiredIdentityRemainsReadable(t *testing.T) {
	f := renewalTestShortAnchor(t, renewalTestStore(t))
	if _, err := f.renew(f.request(t, f.key)); err != nil {
		t.Fatal(err)
	}
	tx, err := f.store.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := waitUntilDatabaseExpiry(t.Context(), tx, f.certificate.NotAfter); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	o := certificateHealthTestOptions()
	o.Filter = "expired"
	r, err := f.store.CertificateHealth(t.Context(), "admin", f.identity.Scope, o)
	if err != nil || len(r.Devices) != 1 || r.Devices[0].CurrentState != "expired" || r.Devices[0].Device.RevokedAt != nil || r.Devices[0].Pending == nil || r.Devices[0].ReplacementState != "valid" {
		t.Fatal("expired certificate health disappeared or implied retirement", err)
	}
}
