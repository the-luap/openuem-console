package windows

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

const wstepTestURL = "https://enroll.example.test/EnrollmentServer/Enrollment.svc"

func wstepTestContext() []EnrollmentContextItem {
	return []EnrollmentContextItem{{"OSEdition", "48"}, {"OSVersion", "10.0.26100.0"}, {"ApplicationVersion", "10.0.26100.0"}, {"DeviceName", "SYNTHETIC-WINDOWS"}, {"DeviceID", "7BA748C8-703E-4DF2-A74A-92984117346A"}, {"DeviceType", "CIMClient_Windows"}, {"EnrollmentType", "Full"}, {"MAC", "00:11:22:33:44:55"}, {"MAC", "00:11:22:33:44:66"}, {"IMEI", "49015420323756"}, {"IMEI", "30215420323756"}, {"EnrollmentData", "untrusted-enrollment-hint"}, {"TargetedUserLoggedIn", "True"}}
}

func wstepTestMessage(der []byte) string {
	base := policyTestMessage()
	start := strings.Index(base, "<s:Body")
	base = base[:start]
	base = strings.NewReplacer(PolicyAction, WSTEPAction, policyTestURL, wstepTestURL).Replace(base)
	var context strings.Builder
	for _, item := range wstepTestContext() {
		context.WriteString(`<ac:ContextItem Name="` + item.Name + `"><ac:Value>`)
		xml.EscapeText(&context, []byte(item.Value))
		context.WriteString(`</ac:Value></ac:ContextItem>`)
	}
	return base + `<s:Body><wst:RequestSecurityToken xmlns:wst="` + trustNS + `"><wst:TokenType>` + deviceTokenType + `</wst:TokenType><wst:RequestType>` + trustNS + `/Issue</wst:RequestType><wsse:BinarySecurityToken ValueType="` + wstepNS + `#PKCS10" EncodingType="` + binaryEncodingType + `">` + base64.StdEncoding.EncodeToString(der) + `</wsse:BinarySecurityToken><ac:AdditionalContext xmlns:ac="` + contextNS + `">` + context.String() + `</ac:AdditionalContext></wst:RequestSecurityToken></s:Body></s:Envelope>`
}

func TestWSTEPRequestGrammarAndPrivacy(t *testing.T) {
	der := []byte{1, 2, 3, 4}
	base := wstepTestMessage(der)
	for name, wire := range map[string]string{
		"published initial shape": base,
		"wrapped base64":          strings.Replace(base, "AQIDBA==", "\n AQID\tBA==\r\n", 1),
		"alternate namespaces":    strings.NewReplacer("xmlns:wst=", "xmlns:trust=", "wst:", "trust:", "xmlns:ac=", "xmlns:context=", "ac:", "context:").Replace(base),
		"device context":          strings.Replace(base, ">Full<", ">Device<", 1),
		"empty enrollment data":   strings.Replace(base, "untrusted-enrollment-hint", "", 1),
		"optional vendor hint":    strings.Replace(base, "</ac:AdditionalContext>", `<ac:ContextItem Name="Vendor.Hint"><ac:Value>untrusted</ac:Value></ac:ContextItem></ac:AdditionalContext>`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			r, err := ParseWSTEPRequest([]byte(wire), wstepTestURL)
			if err != nil || !bytes.Equal(r.CSRDER, der) || r.MessageID != discoveryTestID || r.Credential.Password != "synthetic-secret-marker" {
				t.Fatal("valid WSTEP request changed or rejected")
			}
			if _, err := verifyEnrollmentCSR(r.CSRDER, 2048); !errors.Is(err, ErrCSR) {
				t.Fatal("wire decoding incorrectly verified a CSR")
			}
			encoded, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, marker := range []string{"synthetic-secret-marker", "synthetic@example.test", "untrusted-enrollment-hint", "SYNTHETIC-WINDOWS"} {
				if bytes.Contains(encoded, []byte(marker)) || strings.Contains(fmt.Sprintf("%v %#v", r, r), marker) {
					t.Fatal("request formatting leaks sensitive input")
				}
			}
		})
	}
	if r, err := ParseWSTEPRequest([]byte(base), policyTestURL); err == nil || r != nil {
		t.Fatal("cross-service destination admitted")
	}
}

func TestWSTEPRequestRejectsAmbiguityAndUnsupportedFlows(t *testing.T) {
	base := wstepTestMessage([]byte{1, 2, 3, 4})
	change := func(from, to string) string { return strings.Replace(base, from, to, 1) }
	for name, wire := range map[string]string{
		"wrong action":              change(WSTEPAction, PolicyAction),
		"renewal":                   change(trustNS+"/Issue", trustNS+"/Renew"),
		"wrong token type":          change(deviceTokenType, provisionTokenType),
		"PKCS7":                     change(wstepNS+"#PKCS10", securityNS+"#PKCS7"),
		"wrong encoding":            change(binaryEncodingType, "base64"),
		"qualified type":            change(" ValueType=", " wsse:ValueType="),
		"missing encoding":          change(` EncodingType="`+binaryEncodingType+`"`, ""),
		"duplicate token":           change("</wsse:BinarySecurityToken>", "</wsse:BinarySecurityToken><wsse:BinarySecurityToken/>"),
		"nested token":              change("AQIDBA==", "<Nested>AQIDBA==</Nested>"),
		"URL base64":                change("AQIDBA==", "AQIDBA__"),
		"noncanonical base64":       change("AQIDBA==", "AQIDBB=="),
		"missing base64 padding":    change("AQIDBA==", "AQIDBA"),
		"empty CSR":                 change("AQIDBA==", ""),
		"oversized CSR":             change("AQIDBA==", base64.StdEncoding.EncodeToString(make([]byte, MaxEnrollmentCSRBytes+1))),
		"wrong body namespace":      change(`xmlns:wst="`+trustNS+`"`, `xmlns:wst="urn:wrong"`),
		"context lookalike":         change(`xmlns:ac="`+contextNS+`"`, `xmlns:ac="urn:wrong"`),
		"mixed context":             change("</ac:AdditionalContext>", "untrusted</ac:AdditionalContext>"),
		"duplicate device identity": change(`Name="EnrollmentData"`, `Name="DeviceID"`),
		"missing device name":       change(`Name="DeviceName"`, `Name="IgnoredDeviceName"`),
		"unknown enrollment type":   change(">Full<", ">Unknown<"),
		"unknown device type":       change(">CIMClient_Windows<", ">WindowsDesktop<"),
		"malformed version":         change(">10.0.26100.0<", ">10.0.26100<"),
		"invalid edition":           change(">48<", ">-1<"),
		"invalid boolean":           change(">True<", ">yes<"),
		"qualified context name":    change(` Name="OSEdition"`, ` ac:Name="OSEdition"`),
		"unknown context attribute": change(` Name="OSEdition"`, ` Name="OSEdition" extra="x"`),
		"nested context value":      change(">48<", "><ac:Nested>48</ac:Nested><"),
		"empty device identity":     change("7BA748C8-703E-4DF2-A74A-92984117346A", ""),
		"control device name":       change("SYNTHETIC-WINDOWS", "name&#10;line"),
		"federated authentication":  change("<wsse:UsernameToken ", "<wsse:BinarySecurityToken "),
		"unknown request attribute": change("<wst:RequestSecurityToken ", `<wst:RequestSecurityToken extra="x" `),
		"SOAP required header":      change("</s:Header>", `<x:Required xmlns:x="urn:test" s:mustUnderstand="true"/></s:Header>`),
	} {
		t.Run(name, func(t *testing.T) {
			if r, err := ParseWSTEPRequest([]byte(wire), wstepTestURL); err == nil || r != nil {
				t.Fatal("ambiguous or unsupported enrollment admitted")
			}
		})
	}
	for _, items := range [][]EnrollmentContextItem{nil, append(wstepTestContext(), EnrollmentContextItem{"bad name", "x"}), append(wstepTestContext(), EnrollmentContextItem{strings.Repeat("x", 129), "x"}), append(wstepTestContext(), EnrollmentContextItem{"Hint", strings.Repeat("x", 8193)})} {
		if validateEnrollmentContext(items) == nil {
			t.Fatal("unbounded context admitted")
		}
	}
	for _, count := range []int{maxEnrollmentContextItems + 1, maxEnrollmentContextItems} {
		items := wstepTestContext()
		for len(items) < count {
			items = append(items, EnrollmentContextItem{fmt.Sprintf("Hint%d", len(items)), strings.Repeat("x", 400)})
		}
		if validateEnrollmentContext(items) == nil {
			t.Fatal("aggregate context limit ignored")
		}
	}
}

func TestEnrollmentCSRProofAndPolicy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []x509.SignatureAlgorithm{x509.SHA256WithRSA, x509.SHA256WithRSAPSS} {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted.example.test"}, DNSNames: []string{"untrusted.example.test"}, SignatureAlgorithm: algorithm}, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyEnrollmentCSR(der, 2048); err != nil {
			t.Fatal("valid RSA/SHA256 CSR rejected", err)
		}
		if _, err := verifyEnrollmentCSR(der, 3072); !errors.Is(err, ErrCSR) {
			t.Fatal("issuer key floor ignored")
		}
		changed := bytes.Clone(der)
		changed[len(changed)-1] ^= 1
		for _, invalid := range [][]byte{changed, append(bytes.Clone(der), 0), nil, make([]byte, MaxEnrollmentCSRBytes+1)} {
			if csr, err := verifyEnrollmentCSR(invalid, 2048); !errors.Is(err, ErrCSR) || csr != nil {
				t.Fatal("invalid CSR proof admitted")
			}
		}
		if _, err := verifyEnrollmentCSR(der, 1024); !errors.Is(err, ErrCSR) {
			t.Fatal("invalid issuer key floor admitted")
		}
	}
	for _, algorithm := range []x509.SignatureAlgorithm{x509.SHA1WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA} {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{SignatureAlgorithm: algorithm}, key)
		if err != nil {
			t.Fatal(err)
		}
		if csr, err := verifyEnrollmentCSR(der, 2048); !errors.Is(err, ErrCSR) || csr != nil {
			t.Fatal("CSR violated the advertised SHA256 policy")
		}
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, ec)
	if err != nil {
		t.Fatal(err)
	}
	if csr, err := verifyEnrollmentCSR(der, 2048); !errors.Is(err, ErrCSR) || csr != nil {
		t.Fatal("non-RSA key admitted")
	}
}

func TestEnrollmentRequestDigestBinding(t *testing.T) {
	r := &WSTEPRequest{MessageID: discoveryTestID, CSRDER: []byte{1, 2, 3}, Context: wstepTestContext()}
	original := enrollmentRequestDigest(r)
	copy := *r
	copy.MessageID = "urn:uuid:00112233-4455-4677-8899-aabbccddeeff"
	copy.Context = slices.Clone(r.Context)
	slices.Reverse(copy.Context)
	if !bytes.Equal(original, enrollmentRequestDigest(&copy)) {
		t.Fatal("wire correlation or context order changed retry identity")
	}
	copy.CSRDER = []byte{1, 2, 4}
	if bytes.Equal(original, enrollmentRequestDigest(&copy)) {
		t.Fatal("changed CSR did not change retry identity")
	}
	copy.CSRDER = r.CSRDER
	copy.Context[0].Value += "changed"
	if bytes.Equal(original, enrollmentRequestDigest(&copy)) {
		t.Fatal("changed context did not change retry identity")
	}
}

func TestEnrollmentCSRKeySizeBoundaries(t *testing.T) {
	for _, bits := range []int{1024, 3072, 4096} {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{SignatureAlgorithm: x509.SHA256WithRSA}, key)
		if err != nil {
			t.Fatal(err)
		}
		for _, minimum := range []int{2048, 3072, 4096} {
			csr, err := verifyEnrollmentCSR(der, minimum)
			if bits >= minimum {
				if err != nil || csr == nil {
					t.Fatal("valid RSA policy boundary rejected", bits, minimum)
				}
			} else if !errors.Is(err, ErrCSR) || csr != nil {
				t.Fatal("RSA key below policy floor admitted", bits, minimum)
			}
		}
	}
}

func FuzzWSTEPRequest(f *testing.F) {
	f.Add([]byte(wstepTestMessage([]byte{1, 2, 3, 4})))
	f.Add([]byte("<invalid/>"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseWSTEPRequest(data, wstepTestURL)
		if err != nil {
			if r != nil {
				t.Fatal("parser returned partial protected state")
			}
			return
		}
		if !validMessageID(r.MessageID) || validateEnrollmentContext(r.Context) != nil || len(r.CSRDER) == 0 || len(r.CSRDER) > MaxEnrollmentCSRBytes {
			t.Fatal("parser bypassed a bounded request invariant")
		}
	})
}

// Public synthetic CSR only. Its private key was discarded and is not part of
// the repository. A fixed corpus gives every fuzz worker the same starting input.
//
//go:embed testdata/enrollment-csr.der
var enrollmentFuzzCSR []byte

func FuzzEnrollmentCSR(f *testing.F) {
	if _, err := verifyEnrollmentCSR(enrollmentFuzzCSR, 2048); err != nil {
		f.Fatal("public fuzz fixture is not a valid RSA/SHA256 CSR")
	}
	f.Add(enrollmentFuzzCSR)
	f.Add([]byte{0x30, 0x80, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		csr, err := verifyEnrollmentCSR(data, 2048)
		if err != nil {
			if csr != nil {
				t.Fatal("failed CSR returned a verified key")
			}
			return
		}
		public, ok := csr.PublicKey.(*rsa.PublicKey)
		if !ok || public.N.BitLen() < 2048 || public.N.BitLen() > 4096 || public.E != 65537 || csr.CheckSignature() != nil {
			t.Fatal("CSR verifier bypassed proof or key bounds")
		}
	})
}
