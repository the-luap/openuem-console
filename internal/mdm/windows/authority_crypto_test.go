package windows

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const authorityTestMasterKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

func authorityTestOptions() AuthorityOptions {
	return AuthorityOptions{Organization: "Synthetic & Example", MinimumKeyBits: 2048, ValiditySeconds: 90 * 86400, RenewalSeconds: 14 * 86400}
}

func TestAuthoritySecretAuthentication(t *testing.T) {
	b, err := newAuthoritySecretBox(authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", strings.Repeat("a", 32), authorityTestMasterKey + "\n", strings.Repeat("!", 44), base64.StdEncoding.EncodeToString(make([]byte, 31)), authorityTestMasterKey[:42] + "Z="} {
		if got, err := newAuthoritySecretBox(bad); !errors.Is(err, ErrMasterKey) || got != nil {
			t.Fatal("noncanonical master key admitted")
		}
	}
	var missing *authoritySecretBox
	if _, err := missing.open(nil, "purpose"); !errors.Is(err, ErrMasterKey) {
		t.Fatal(err)
	}
	if _, err := missing.seal([]byte("secret"), "purpose"); !errors.Is(err, ErrMasterKey) {
		t.Fatal(err)
	}
	plain := []byte("synthetic private key bytes")
	one, err := b.seal(plain, "purpose")
	if err != nil {
		t.Fatal(err)
	}
	two, err := b.seal(plain, "purpose")
	if err != nil || bytes.Equal(one, two) || bytes.Contains(one, plain) {
		t.Fatal("encryption is not randomized")
	}
	got, err := b.open(one, "purpose")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("authenticated round trip failed")
	}
	for i := range one {
		changed := bytes.Clone(one)
		changed[i] ^= 1
		if got, err := b.open(changed, "purpose"); !errors.Is(err, ErrAuthoritySecret) || got != nil {
			t.Fatal("modified envelope admitted")
		}
	}
	for _, purpose := range []string{"", "another purpose", strings.Repeat("x", 1025)} {
		if got, err := b.open(one, purpose); !errors.Is(err, ErrAuthoritySecret) || got != nil {
			t.Fatal("wrong context admitted")
		}
	}
	for _, bad := range [][]byte{nil, one[:29], append(bytes.Clone(one), 0), make([]byte, 8222)} {
		if got, err := b.open(bad, "purpose"); !errors.Is(err, ErrAuthoritySecret) || got != nil {
			t.Fatal("invalid envelope admitted")
		}
	}
	for _, n := range []int{0, maxAuthoritySecretBytes + 1} {
		if _, err := b.seal(make([]byte, n), "purpose"); !errors.Is(err, ErrAuthoritySecret) {
			t.Fatal("invalid plaintext size admitted")
		}
	}
	for _, purpose := range []string{"", strings.Repeat("x", 1025)} {
		if _, err := b.seal(plain, purpose); !errors.Is(err, ErrAuthoritySecret) {
			t.Fatal("invalid encryption context admitted")
		}
	}
	boundary := bytes.Repeat([]byte{42}, maxAuthoritySecretBytes)
	encrypted, err := b.seal(boundary, strings.Repeat("x", 1024))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.open(encrypted, strings.Repeat("x", 1024)); err != nil || !bytes.Equal(got, boundary) {
		t.Fatal("valid size boundary rejected")
	}
	other, _ := newAuthoritySecretBox(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if got, err := other.open(one, "purpose"); !errors.Is(err, ErrAuthoritySecret) || got != nil {
		t.Fatal("wrong master key admitted")
	}
}

func TestAuthorityCertificateAndProtectedSigner(t *testing.T) {
	now := time.Now().UTC()
	a := EnrollmentAuthority{ID: "00112233-4455-4677-8899-aabbccddeeff", TenantID: 1, AuthorityOptions: authorityTestOptions(), CreatedAt: now, CreatedBy: "synthetic"}
	certificate, private, err := generateAuthorityCertificate(a, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	a.Certificate = certificate
	cert, err := x509.ParseCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	a.ExpiresAt = cert.NotAfter
	if _, err := parseAuthorityCertificate(a); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatal(err)
	}
	if !cert.NotBefore.Equal(now.Add(-5*time.Minute).Truncate(time.Second)) || !cert.NotAfter.Equal(now.Add(5*365*24*time.Hour).Truncate(time.Second)) {
		t.Fatal("unexpected root lifetime")
	}
	box, _ := newAuthoritySecretBox(authorityTestMasterKey)
	s := &Store{secrets: box}
	encrypted, err := box.seal(private, authoritySecretPurpose(a))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := s.decryptAuthority(a, encrypted, now)
	if err != nil || !signer.key.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("protected CA cannot be loaded")
	}
	if fmt.Sprint(*signer) != "[protected native Windows CA]" || fmt.Sprintf("%#v", *signer) != "[protected native Windows CA]" {
		t.Fatal("signer formatting leaks internals")
	}
	for name, change := range map[string]func(*EnrollmentAuthority){
		"organization":    func(a *EnrollmentAuthority) { a.Organization = "Foreign" },
		"tenant":          func(a *EnrollmentAuthority) { a.TenantID = 2 },
		"identity":        func(a *EnrollmentAuthority) { a.ID = "10112233-4455-4677-8899-aabbccddeeff" },
		"key policy":      func(a *EnrollmentAuthority) { a.MinimumKeyBits = 4096 },
		"validity":        func(a *EnrollmentAuthority) { a.ValiditySeconds++ },
		"renewal":         func(a *EnrollmentAuthority) { a.RenewalSeconds++ },
		"expiry":          func(a *EnrollmentAuthority) { a.ExpiresAt = a.ExpiresAt.Add(time.Second) },
		"future creation": func(a *EnrollmentAuthority) { a.CreatedAt = now.Add(time.Hour) },
		"certificate": func(a *EnrollmentAuthority) {
			a.Certificate = bytes.Clone(a.Certificate)
			a.Certificate[len(a.Certificate)-1] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := a
			change(&changed)
			if got, err := s.decryptAuthority(changed, encrypted, now); err == nil || got != nil {
				t.Fatal("modified authority admitted")
			}
		})
	}
	for _, when := range []time.Time{cert.NotBefore.Add(-time.Second), cert.NotAfter, cert.NotAfter.Add(-time.Duration(a.ValiditySeconds) * time.Second)} {
		if got, err := s.decryptAuthority(a, encrypted, when); !errors.Is(err, ErrAuthorityUnavailable) || got != nil {
			t.Fatal("authority outside issuance window admitted")
		}
	}
	if _, err := (&Store{}).decryptAuthority(a, encrypted, now); !errors.Is(err, ErrMasterKey) {
		t.Fatal(err)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	wrongDER, err := x509.MarshalPKCS8PrivateKey(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{[]byte("invalid DER"), wrongDER} {
		sealed, err := box.seal(bad, authoritySecretPurpose(a))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := s.decryptAuthority(a, sealed, now); !errors.Is(err, ErrAuthoritySecret) || got != nil {
			t.Fatal("invalid or mismatched key admitted")
		}
	}
	clear(wrongDER)
}

func TestAuthorityOptionsBoundaries(t *testing.T) {
	for _, change := range []func(*AuthorityOptions){
		func(o *AuthorityOptions) { o.Organization = "" }, func(o *AuthorityOptions) { o.Organization = " padded" },
		func(o *AuthorityOptions) { o.Organization = strings.Repeat("x", 129) }, func(o *AuthorityOptions) { o.Organization = "a\nb" },
		func(o *AuthorityOptions) { o.Organization = string([]byte{255}) }, func(o *AuthorityOptions) { o.MinimumKeyBits = 1024 },
		func(o *AuthorityOptions) { o.ValiditySeconds = 86399 }, func(o *AuthorityOptions) { o.ValiditySeconds = 365*86400 + 1 },
		func(o *AuthorityOptions) { o.RenewalSeconds = 3599 }, func(o *AuthorityOptions) { o.RenewalSeconds = o.ValiditySeconds },
	} {
		o := authorityTestOptions()
		change(&o)
		if !errors.Is(o.validate(), ErrAuthority) {
			t.Fatal("invalid CA policy admitted")
		}
	}
	for _, bits := range []int{2048, 3072, 4096} {
		for _, validity := range []int64{86400, 365 * 86400} {
			o := AuthorityOptions{Organization: strings.Repeat("x", 128), MinimumKeyBits: bits, ValiditySeconds: validity, RenewalSeconds: 3600}
			if err := o.validate(); err != nil {
				t.Fatal("valid CA policy boundary rejected")
			}
		}
	}
}
