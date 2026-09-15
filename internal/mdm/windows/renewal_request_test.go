package windows

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const renewalSOAPUsername = `<wsse:UsernameToken wsu:Id="account"><wsse:Username>synthetic-renewal-hint@example.test</wsse:Username><wsse:Password wsse:Type="` + passwordTextType + `"></wsse:Password></wsse:UsernameToken>`

func renewalSOAPTimestamp(created, expires time.Time) string {
	return `<wsu:Timestamp wsu:Id="timestamp"><wsu:Created>` + created.UTC().Format(time.RFC3339Nano) + `</wsu:Created><wsu:Expires>` + expires.UTC().Format(time.RFC3339Nano) + `</wsu:Expires></wsu:Timestamp>`
}

func renewalSOAPTestMessage(cms []byte, security string) string {
	return `<s:Envelope xmlns:s="` + soapNS + `" xmlns:a="` + addressingNS + `" xmlns:wsse="` + securityNS + `" xmlns:wsu="` + securityUtilityNS + `" xmlns:wst="` + trustNS + `" xmlns:ac="` + contextNS + `"><s:Header><a:Action s:mustUnderstand="1">` + WSTEPAction + `</a:Action><a:MessageID>` + discoveryTestID + `</a:MessageID><a:ReplyTo><a:Address>` + addressingNS + `/anonymous</a:Address></a:ReplyTo><a:To s:mustUnderstand="1">` + wstepTestURL + `</a:To>` + security + `</s:Header><s:Body><wst:RequestSecurityToken><wst:TokenType>` + deviceTokenType + `</wst:TokenType><wst:RequestType>` + trustNS + `/Renew</wst:RequestType><wsse:BinarySecurityToken ValueType="` + securityNS + `#PKCS7" EncodingType="` + binaryEncodingType + `">` + base64.StdEncoding.EncodeToString(cms) + `</wsse:BinarySecurityToken><ac:AdditionalContext><ac:ContextItem Name="DeviceType"><ac:Value>CIMClient_Windows</ac:Value></ac:ContextItem><ac:ContextItem Name="ApplicationVersion"><ac:Value>10.0.26100.0</ac:Value></ac:ContextItem></ac:AdditionalContext></wst:RequestSecurityToken></s:Body></s:Envelope>`
}

func TestWSTEPRenewalGrammarAndPrivacy(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 123000000, time.UTC)
	timestamp := renewalSOAPTimestamp(now, now.Add(5*time.Minute))
	for name, security := range map[string]string{
		"no security header": "",
		"empty security":     "<wsse:Security/>",
		"timestamp":          `<wsse:Security s:mustUnderstand="1">` + timestamp + `</wsse:Security>`,
		"account hint":       `<wsse:Security>` + renewalSOAPUsername + `</wsse:Security>`,
		"published shape":    `<wsse:Security s:mustUnderstand="true">` + timestamp + renewalSOAPUsername + `</wsse:Security>`,
		"alternate order":    `<wsse:Security>` + renewalSOAPUsername + timestamp + `</wsse:Security>`,
	} {
		t.Run(name, func(t *testing.T) {
			data := []byte(renewalSOAPTestMessage([]byte{1, 2, 3, 4}, security))
			r, err := ParseWSTEPRenewalRequest(data, wstepTestURL)
			if err != nil || r.MessageID != discoveryTestID || !bytes.Equal(r.CMSDER, []byte{1, 2, 3, 4}) {
				t.Fatal("valid renewal wire rejected", err)
			}
			if r.CreatedAt != nil && (!r.CreatedAt.Equal(now) || !r.ExpiresAt.Equal(now.Add(5*time.Minute))) {
				t.Fatal("timestamp changed")
			}
			if initial, err := ParseWSTEPRequest(data, wstepTestURL); err == nil || initial != nil {
				t.Fatal("renewal fell into initial issuance")
			}
			encoded, err := json.Marshal(r)
			if err != nil || bytes.Contains(encoded, []byte("AQIDBA==")) || bytes.Contains(encoded, []byte("synthetic-renewal-hint")) || strings.Contains(fmt.Sprintf("%+v %#v", r, r), "synthetic-renewal-hint") {
				t.Fatal("renewal parser leaked input")
			}
		})
	}
	base := renewalSOAPTestMessage([]byte{1, 2, 3, 4}, "")
	start, end := strings.Index(base, "<ac:AdditionalContext>"), strings.Index(base, "</ac:AdditionalContext>")+len("</ac:AdditionalContext>")
	for _, wire := range []string{
		base[:start] + base[end:],
		base[:start] + "<ac:AdditionalContext/>" + base[end:],
		strings.Replace(base, "AQIDBA==", "\n AQID\tBA==\r\n", 1),
		strings.NewReplacer("xmlns:wst=", "xmlns:trust=", "wst:", "trust:").Replace(base),
		strings.Replace(base, "</ac:AdditionalContext>", `<ac:ContextItem Name="TenantID"><ac:Value>2</ac:Value></ac:ContextItem></ac:AdditionalContext>`, 1),
	} {
		if _, err := ParseWSTEPRenewalRequest([]byte(wire), wstepTestURL); err != nil {
			t.Fatal("optional renewal context or XML alias rejected", err)
		}
	}
	if _, err := ParseWSTEPRenewalRequest([]byte(base), policyTestURL); err == nil {
		t.Fatal("wrong endpoint admitted")
	}
	max := renewalSOAPTestMessage(make([]byte, MaxWindowsRenewalProofBytes), "")
	if r, err := ParseWSTEPRenewalRequest([]byte(max), wstepTestURL); err != nil || len(r.CMSDER) != MaxWindowsRenewalProofBytes {
		t.Fatal("documented CMS bound not supported", err)
	}
}

func TestWSTEPRenewalRejectsMixedAuthenticationAndAmbiguity(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	timestamp := renewalSOAPTimestamp(now, now.Add(5*time.Minute))
	base := renewalSOAPTestMessage([]byte{1, 2, 3, 4}, `<wsse:Security s:mustUnderstand="1">`+timestamp+renewalSOAPUsername+`</wsse:Security>`)
	change := func(from, to string) string { return strings.Replace(base, from, to, 1) }
	for name, wire := range map[string]string{
		"issue":                 change(trustNS+"/Renew", trustNS+"/Issue"),
		"other operation":       change(trustNS+"/Renew", trustNS+"/Validate"),
		"wrong action":          change(WSTEPAction, PolicyAction),
		"wrong token":           change(deviceTokenType, provisionTokenType),
		"PKCS10":                change(securityNS+"#PKCS7", wstepNS+"#PKCS10"),
		"wrong PKCS7 namespace": change(securityNS+"#PKCS7", wstepNS+"#PKCS7"),
		"duplicate type":        change("</wst:RequestType>", "</wst:RequestType><wst:RequestType>"+trustNS+"/Renew</wst:RequestType>"),
		"extra body field":      change("</wst:RequestSecurityToken>", "<wst:Extra/></wst:RequestSecurityToken>"),
		"lookalike context":     change("xmlns:ac=\""+contextNS+"\"", "xmlns:ac=\"urn:other\""),
		"duplicate hint":        change(`Name="ApplicationVersion"`, `Name="DeviceType"`),
		"bad version":           change("10.0.26100.0", "10.0"),
		"nested binary":         change("AQIDBA==", "<wst:Nested>AQIDBA==</wst:Nested>"),
		"binary attribute":      change(" ValueType=", " wsse:ValueType="),
		"missing encoding":      change(` EncodingType="`+binaryEncodingType+`"`, ""),
		"noncanonical base64":   change("AQIDBA==", "AQIDBB=="),
		"unpadded base64":       change("AQIDBA==", "AQIDBA"),
		"URL base64":            change("AQIDBA==", "AQIDBA__"),
		"empty binary":          change("AQIDBA==", ""),
		"oversized binary":      change("AQIDBA==", base64.StdEncoding.EncodeToString(make([]byte, MaxWindowsRenewalProofBytes+1))),
		"account password":      change(`"></wsse:Password>`, `">synthetic-secret</wsse:Password>`),
		"duplicate security":    change("</wsse:Security>", "</wsse:Security><wsse:Security/>"),
		"duplicate timestamp":   change(timestamp, timestamp+timestamp),
		"duplicate identifier":  change(`wsu:Id="account"`, `wsu:Id="timestamp"`),
		"invalid identifier":    change(`wsu:Id="timestamp"`, `wsu:Id="invalid name"`),
		"missing identifier":    change(` wsu:Id="timestamp"`, ""),
		"qualified identifier":  change(`wsu:Id="timestamp"`, `wsse:Id="timestamp"`),
		"federated token":       change(renewalSOAPUsername, `<wsse:BinarySecurityToken wsu:Id="account">unverified</wsse:BinarySecurityToken>`),
		"empty account":         change("synthetic-renewal-hint@example.test", ""),
		"password type":         change(passwordTextType, "PasswordDigest"),
		"security signature":    change(renewalSOAPUsername, `<wsse:Signature wsu:Id="account"/>`),
		"missing expiry":        change("<wsu:Expires>2026-09-10T12:05:00Z</wsu:Expires>", ""),
		"equal timestamp":       change("2026-09-10T12:05:00Z", "2026-09-10T12:00:00Z"),
		"long timestamp":        change("2026-09-10T12:05:00Z", "2026-09-10T12:11:00Z"),
		"timestamp zone":        change("2026-09-10T12:05:00Z", "2026-09-10T12:05:00+00:00"),
		"timestamp lookalike":   change("<wsu:Created>", "<wsse:Created>"),
		"required header":       change("</s:Header>", `<unknown xmlns="urn:other" s:mustUnderstand="true"/></s:Header>`),
	} {
		t.Run(name, func(t *testing.T) {
			if r, err := ParseWSTEPRenewalRequest([]byte(wire), wstepTestURL); err == nil || r != nil {
				t.Fatal("ambiguous or unsupported renewal accepted")
			}
		})
	}
	if r, err := ParseWSTEPRenewalRequest([]byte(strings.Repeat(" ", MaxWSTEPBytes)+base), wstepTestURL); err == nil || r != nil {
		t.Fatal("SOAP body bound ignored")
	}
}

func FuzzWSTEPRenewalRequest(f *testing.F) {
	f.Add([]byte(renewalSOAPTestMessage([]byte{1, 2, 3, 4}, "")))
	f.Add([]byte(renewalSOAPTestMessage([]byte{1, 2, 3, 4}, `<wsse:Security>`+renewalSOAPUsername+`</wsse:Security>`)))
	f.Add([]byte(wstepTestMessage([]byte{1, 2, 3, 4})))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseWSTEPRenewalRequest(data, wstepTestURL)
		if err != nil {
			if r != nil {
				t.Fatal("parser returned partial renewal on error")
			}
			return
		}
		if r == nil || len(r.CMSDER) == 0 || len(r.CMSDER) > MaxWindowsRenewalProofBytes || !validMessageID(r.MessageID) || (r.CreatedAt == nil) != (r.ExpiresAt == nil) {
			t.Fatal("parser broke renewal invariants")
		}
		if initial, err := ParseWSTEPRequest(data, wstepTestURL); err == nil || initial != nil {
			t.Fatal("renewal and initial operation overlap")
		}
	})
}
