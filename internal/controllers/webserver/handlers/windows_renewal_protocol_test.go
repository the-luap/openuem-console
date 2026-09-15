package handlers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/smallstep/pkcs7"
)

// Independent ephemeral CSR/CMS encoders exercise production issuance. These
// fixtures never install keys, certificates or profiles on the host.
type windowsRenewalConsolePeer struct {
	deviceID          string
	certificate       *x509.Certificate
	key, candidateKey *rsa.PrivateKey
}

func newWindowsRenewalConsolePeer(t *testing.T, h *Handler, ctx context.Context, scope access.Scope) windowsRenewalConsolePeer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	next, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Synthetic renewal console peer"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	invitation, credential, err := h.Windows.CreateEnrollmentInvitation(ctx, "apple-console-admin", scope, "renewal-console@example.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	response, err := h.Windows.EnrollWindows(ctx, &windows.WSTEPRequest{MessageID: "urn:uuid:" + uuid.NewString(), Credential: *credential, CSRDER: csr, Context: []windows.EnrollmentContextItem{
		{Name: "OSEdition", Value: "48"}, {Name: "OSVersion", Value: "10.0.26100.0"}, {Name: "ApplicationVersion", Value: "10.0.26100.0"}, {Name: "DeviceName", Value: "Synthetic renewal <script>peer</script>"}, {Name: "DeviceID", Value: uuid.NewString()}, {Name: "DeviceType", Value: "CIMClient_Windows"}, {Name: "EnrollmentType", Value: "Full"},
	}}, h.WindowsOptions)
	clear(response)
	if err != nil {
		t.Fatal(err)
	}
	var deviceID string
	var der []byte
	if err := h.Model.DB.QueryRowContext(ctx, `SELECT e.device_id,c.certificate FROM mdm_windows_enrollments e JOIN mdm_windows_device_certificates c ON c.id=e.certificate_id WHERE e.invitation_id=$1`, invitation.ID).Scan(&deviceID, &der); err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	// The supported test CA opens its renewal window after one second.
	delay := time.Until(certificate.NotAfter.Add(-86399*time.Second)) + 10*time.Millisecond
	if delay > 2*time.Second {
		t.Fatal("unexpected synthetic renewal window")
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	return windowsRenewalConsolePeer{deviceID, certificate, key, next}
}

func (p windowsRenewalConsolePeer) renew(t *testing.T, h *Handler, ctx context.Context, scope access.Scope) windows.CertificateRenewal {
	t.Helper()
	// Each intent has a fresh subject nonce so canceled CSR retries are not
	// mistaken for a new request. The issuer owns the resulting certificate name.
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: uuid.NewString()}, SignatureAlgorithm: x509.SHA256WithRSA}, p.candidateKey)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Info      asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	var info struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue
		} `asn1:"set,tag:0"`
	}
	if rest, err := asn1.Unmarshal(csr, &wire); err != nil || len(rest) != 0 {
		t.Fatal("invalid synthetic CSR wire")
	}
	if rest, err := asn1.Unmarshal(wire.Info.FullBytes, &info); err != nil || len(rest) != 0 {
		t.Fatal("invalid synthetic CSR info")
	}
	info.Attributes = append(info.Attributes, struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue
	}{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 13, 1}, asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: p.certificate.Raw}})
	data, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.candidateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	wire.Info = asn1.RawValue{FullBytes: data}
	wire.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	csr, err = asn1.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pkcs7.NewSignedData(csr)
	if err != nil {
		t.Fatal(err)
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err = signed.AddSigner(p.certificate, p.key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	cms, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	response, err := h.Windows.RenewWindowsCertificate(ctx, p.certificate, windows.CertificateRenewalRequest{MessageID: "urn:uuid:" + uuid.NewString(), CMSDER: cms}, h.WindowsOptions)
	clear(response)
	if err != nil {
		t.Fatal(err)
	}
	history, err := h.Windows.CertificateRenewals(ctx, "apple-console-admin", scope, p.deviceID, 0, 1)
	if err != nil || len(history) != 1 || history[0].Phase != "pending" {
		t.Fatal("synthetic renewal did not persist", err)
	}
	return history[0]
}

func assertWindowsRenewalConsoleAccess(t *testing.T, h *Handler, ctx context.Context, certificate *x509.Certificate, allowed bool) {
	t.Helper()
	request := httptest.NewRequest("POST", h.WindowsOptions.ManagementURL, nil).WithContext(ctx)
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{certificate}}
	identity, err := h.Windows.AuthenticateManagementDevice(request, h.WindowsOptions)
	if allowed && (err != nil || identity == nil) {
		t.Fatal("current certificate access was lost", err)
	}
	if !allowed && (!errors.Is(err, windows.ErrManagementIdentity) || identity != nil) {
		t.Fatal("canceled replacement retained access", err)
	}
}
