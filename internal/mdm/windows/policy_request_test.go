package windows

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"testing"
)

const policyTestURL = "https://enroll.example.test/EnrollmentServer/Policy.svc"

func policyTestMessage() string {
	return `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<s:Header>
  <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies</a:Action>
  <a:MessageID>` + discoveryTestID + `</a:MessageID>
  <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
  <a:To s:mustUnderstand="1">` + policyTestURL + `</a:To>
  <wsse:Security s:mustUnderstand="1">
    <wsse:UsernameToken u:Id="uuid-cc1ccc1f-2fba-4bcf-b063-ffc0cac77917-4">
      <wsse:Username>synthetic@example.test</wsse:Username>
      <wsse:Password wsse:Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">synthetic-secret-marker</wsse:Password>
    </wsse:UsernameToken>
  </wsse:Security>
</s:Header>
<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
    <client><lastUpdate xsi:nil="true"/><preferredLanguage xsi:nil="true"/></client>
    <requestFilter xsi:nil="true"/>
  </GetPolicies>
</s:Body>
</s:Envelope>`
}

func TestPolicyRequestUsernameToken(t *testing.T) {
	base := policyTestMessage()
	for name, wire := range map[string]string{
		"Microsoft example shape":   base,
		"unqualified password Type": strings.ReplaceAll(base, "wsse:Type=", "Type="),
		"numeric nil values":        strings.ReplaceAll(base, `xsi:nil="true"`, `xsi:nil="1"`),
		"alternate utility prefix":  strings.NewReplacer("xmlns:u=", "xmlns:utility=", " u:Id=", " utility:Id=").Replace(base),
		"alternate security prefix": strings.NewReplacer("xmlns:wsse=", "xmlns:security=", "wsse:", "security:").Replace(base),
		"opaque token label":        strings.ReplaceAll(base, "uuid-cc1ccc1f-2fba-4bcf-b063-ffc0cac77917-4", "another_token-label.1"),
	} {
		t.Run(name, func(t *testing.T) {
			request, err := ParsePolicyRequest([]byte(wire), policyTestURL)
			if err != nil {
				t.Fatal(err)
			}
			if request.MessageID != discoveryTestID || request.Credential.Username != "synthetic@example.test" || request.Credential.Password != "synthetic-secret-marker" {
				t.Fatal("credential or correlation changed")
			}
		})
	}
	for _, password := range []struct{ wire, want string }{
		{"  literal space  ", "  literal space  "}, {"&lt;xml&gt;&amp;&#13;&#10;", "<xml>&\r\n"}, {"line\r\nfeed", "line\nfeed"}, {"\t", "\t"},
	} {
		request, err := ParsePolicyRequest([]byte(strings.ReplaceAll(base, "synthetic-secret-marker", password.wire)), policyTestURL)
		if err != nil || request.Credential.Password != password.want {
			t.Fatal("secret text was normalized beyond XML line-ending/entity processing")
		}
	}
}

func TestPolicyRequestRejectsCredentialAndBodyAmbiguity(t *testing.T) {
	base := policyTestMessage()
	replace := func(old, new string) string { return strings.Replace(base, old, new, 1) }
	cases := map[string]string{
		"discovery instead of policy":     replace(PolicyAction, DiscoveryAction),
		"wrong destination":               replace(policyTestURL, discoveryTestURL),
		"duplicate security":              replace("</wsse:Security>", "</wsse:Security><wsse:Security/>"),
		"wrong security namespace":        replace(securityNS+`"`, `urn:wrong"`),
		"no security":                     replace("<wsse:Security ", "<wsse:Unknown "),
		"federated token":                 replace("<wsse:UsernameToken ", "<wsse:BinarySecurityToken "),
		"certificate signature":           replace("<wsse:UsernameToken ", "<wsse:Signature "),
		"timestamp beside username token": replace("</wsse:Security>", "<u:Timestamp/></wsse:Security>"),
		"duplicate username token":        replace("</wsse:UsernameToken>", "</wsse:UsernameToken><wsse:UsernameToken/>"),
		"token mixed text":                replace("</wsse:UsernameToken>", "synthetic-secret-marker</wsse:UsernameToken>"),
		"missing token label":             replace(` u:Id="uuid-cc1ccc1f-2fba-4bcf-b063-ffc0cac77917-4"`, ""),
		"unqualified token label":         replace("u:Id=", "Id="),
		"empty token label":               replace("uuid-cc1ccc1f-2fba-4bcf-b063-ffc0cac77917-4", ""),
		"oversized token label":           replace("uuid-cc1ccc1f-2fba-4bcf-b063-ffc0cac77917-4", strings.Repeat("a", 129)),
		"invalid token label":             replace("uuid-cc1ccc1f-2fba-4bcf-b063-ffc0cac77917-4", "id/label"),
		"namespace in token label":        replace("uuid-cc1ccc1f-2fba-4bcf-b063-ffc0cac77917-4", "id:label"),
		"whitespace token label":          replace("uuid-cc1ccc1f-2fba-4bcf-b063-ffc0cac77917-4", "id label"),
		"leading digit token label":       replace("uuid-cc1ccc1f-2fba-4bcf-b063-ffc0cac77917-4", "1-id"),
		"unknown token attribute":         replace("<wsse:UsernameToken ", `<wsse:UsernameToken extra="value" `),
		"duplicate username":              replace("</wsse:Username>", "</wsse:Username><wsse:Username>other@example.test</wsse:Username>"),
		"username lookalike":              replace("<wsse:Username>", `<wsse:Username xmlns:wsse="urn:wrong">`),
		"empty username":                  replace("synthetic@example.test", ""),
		"oversized username":              replace("synthetic@example.test", strings.Repeat("a", 513)),
		"control in username":             replace("synthetic@example.test", "synthetic&#10;@example.test"),
		"empty password":                  replace("synthetic-secret-marker", ""),
		"oversized password":              replace("synthetic-secret-marker", strings.Repeat("a", 1025)),
		"password digest":                 replace(passwordTextType, strings.ReplaceAll(passwordTextType, "PasswordText", "PasswordDigest")),
		"password unknown type namespace": replace("wsse:Type=", "u:Type="),
		"password duplicate Type":         replace("wsse:Type=", `Type="ignored" wsse:Type=`),
		"password type missing":           replace(` wsse:Type="`+passwordTextType+`"`, ""),
		"nested password":                 replace("synthetic-secret-marker", "<wsse:Nested/>"),
		"password lookalike":              replace("<wsse:Password ", `<wsse:Password xmlns:wsse="urn:wrong" `),
		"duplicate password":              replace("</wsse:Password>", "</wsse:Password><wsse:Password/>"),
		"unknown policy field":            replace("</GetPolicies>", "<unknown/></GetPolicies>"),
		"policy namespace lookalike":      replace(PolicyNamespace+`"`, `urn:wrong"`),
		"policy mixed text":               replace("</GetPolicies>", "text</GetPolicies>"),
		"client namespace lookalike":      replace("<client>", `<client xmlns="urn:wrong">`),
		"client duplicate nil field":      replace(`<lastUpdate xsi:nil="true"/>`, `<preferredLanguage xsi:nil="true"/>`),
		"client missing nil field":        replace(`<lastUpdate xsi:nil="true"/>`, ""),
		"client unknown attribute":        replace("<client>", `<client name="ignored">`),
		"non-null last update":            replace(`<lastUpdate xsi:nil="true"/>`, "<lastUpdate>2026-09-09T00:00:00Z</lastUpdate>"),
		"missing nil attribute":           replace(`<lastUpdate xsi:nil="true"/>`, "<lastUpdate/>"),
		"non-null preferred language":     replace(`<preferredLanguage xsi:nil="true"/>`, "<preferredLanguage>en-US</preferredLanguage>"),
		"request filter false nil":        replace(`<requestFilter xsi:nil="true"/>`, `<requestFilter xsi:nil="false"/>`),
		"request filter text":             replace(`<requestFilter xsi:nil="true"/>`, `<requestFilter xsi:nil="true">text</requestFilter>`),
		"request filter nested":           replace(`<requestFilter xsi:nil="true"/>`, `<requestFilter xsi:nil="true"><other/></requestFilter>`),
		"request filter lookalike":        replace(`<requestFilter xsi:nil="true"/>`, `<requestFilter xmlns="urn:wrong" xsi:nil="true"/>`),
		"oversized message":               base + strings.Repeat(" ", MaxPolicyBytes),
	}
	// Well-formed requests with another WS-Security mechanism must also fail,
	// independently of the malformed closing-tag cases above.
	cases["well-formed federated token"] = strings.ReplaceAll(base, "UsernameToken", "BinarySecurityToken")
	cases["well-formed signature"] = strings.ReplaceAll(base, "UsernameToken", "Signature")
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			request, err := ParsePolicyRequest([]byte(wire), policyTestURL)
			if err == nil || request != nil {
				t.Fatal("ambiguous policy or credential was admitted")
			}
			if strings.Contains(err.Error(), "synthetic") {
				t.Fatal("request values escaped through an error")
			}
		})
	}
}

func TestPolicyCredentialFormattingIsRedacted(t *testing.T) {
	request, err := ParsePolicyRequest([]byte(policyTestMessage()), policyTestURL)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	xmlEncoded, err := xml.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{string(encoded), string(xmlEncoded), fmt.Sprint(request.Credential), fmt.Sprintf("%+v", request), fmt.Sprintf("%#v", *request), fmt.Sprintf("%s", request.Credential)} {
		if strings.Contains(value, "synthetic-secret-marker") || strings.Contains(value, "synthetic@example.test") {
			t.Fatal("default formatting exposed enrollment credentials")
		}
	}
}

func FuzzPolicyRequest(f *testing.F) {
	f.Add([]byte(policyTestMessage()))
	f.Add([]byte(discoveryTestMessage()))
	f.Fuzz(func(t *testing.T, wire []byte) {
		request, err := ParsePolicyRequest(wire, policyTestURL)
		if err != nil {
			if request != nil {
				t.Fatal("partial credentials returned on failure")
			}
			return
		}
		if request == nil || len(request.Credential.Username) < 1 || len(request.Credential.Username) > 512 || len(request.Credential.Password) < 1 || len(request.Credential.Password) > 1024 {
			t.Fatal("credential bounds violated")
		}
	})
}
