package windows

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const discoveryTestURL = "https://enroll.example.test/EnrollmentServer/Discovery.svc"
const discoveryTestID = "urn:uuid:d62c6720-0989-4a51-a1b6-103491d8eca4"

// Synthetic account and device hints in the wire shape from MS-MDE2 sections
// 3.1.4.1 and 4.1. No request or credential captured from a real device is used.
func discoveryTestMessage() string {
	return `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/Discover</a:Action>
    <a:MessageID>` + discoveryTestID + `</a:MessageID>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
    <a:To s:mustUnderstand="1">` + discoveryTestURL + `</a:To>
  </s:Header>
  <s:Body>
    <Discover xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment/">
      <request xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <EmailAddress>synthetic@example.test</EmailAddress>
        <OSEdition>48</OSEdition>
        <RequestVersion>5.0</RequestVersion>
        <DeviceType>CIMClient_Windows</DeviceType>
        <ApplicationVersion>10.0.26100.1</ApplicationVersion>
        <AuthPolicies><AuthPolicy>OnPremise</AuthPolicy><AuthPolicy>Federated</AuthPolicy><AuthPolicy>Certificate</AuthPolicy></AuthPolicies>
      </request>
    </Discover>
  </s:Body>
</s:Envelope>`
}

func TestDiscoveryWireRequests(t *testing.T) {
	base := discoveryTestMessage()
	for name, wire := range map[string]string{
		"published namespace":        base,
		"normative namespace":        strings.ReplaceAll(base, EnrollmentNamespace+`/"`, EnrollmentNamespace+`"`),
		"different prefixes":         strings.NewReplacer("xmlns:s=", "xmlns:soap=", "<s:", "<soap:", "</s:", "</soap:", " s:", " soap:", "xmlns:a=", "xmlns:wsa=", "<a:", "<wsa:", "</a:", "</wsa:").Replace(base),
		"UTF-8 BOM":                  "\xef\xbb\xbf" + base,
		"unsigned OS edition":        strings.ReplaceAll(base, ">48<", ">4294967295<"),
		"domain user":                strings.ReplaceAll(base, "synthetic@example.test", `EXAMPLE\synthetic`),
		"false nil marker":           strings.ReplaceAll(base, `<AuthPolicies>`, `<AuthPolicies i:nil="false">`),
		"anonymous reply omitted":    strings.ReplaceAll(base, `<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>`, ""),
		"optional extension":         strings.ReplaceAll(base, "</s:Header>", `<x:Hint xmlns:x="urn:example:optional" s:mustUnderstand="0">ignored</x:Hint></s:Header>`),
		"host case and default port": strings.ReplaceAll(base, "https://enroll.example.test/", "https://ENROLL.example.test:443/"),
		"legacy device grammar":      strings.ReplaceAll(base, "CIMClient_Windows", "WindowsPhone"),
	} {
		t.Run(name, func(t *testing.T) {
			request, err := ParseDiscovery([]byte(wire), discoveryTestURL)
			if err != nil || request == nil {
				t.Fatalf("parse: %v", err)
			}
			if request.MessageID != discoveryTestID || request.RequestVersion != 5 || strings.Join(request.AuthPolicies, ",") != "OnPremise,Federated,Certificate" {
				t.Fatal("correlation, version or authentication policy order changed")
			}
		})
	}
	for version := 1; version <= 9; version++ {
		for _, lexical := range []string{fmt.Sprint(version), fmt.Sprintf("%d.0", version), fmt.Sprintf("+0%d.00", version)} {
			request, err := ParseDiscovery([]byte(strings.ReplaceAll(base, ">5.0<", ">"+lexical+"<")), discoveryTestURL)
			if err != nil || request.RequestVersion != version {
				t.Fatalf("version %s: %v", lexical, err)
			}
		}
	}
}

func TestDiscoveryRejectsMalformedRequests(t *testing.T) {
	base := discoveryTestMessage()
	replace := func(old, new string) string { return strings.Replace(base, old, new, 1) }
	cases := map[string]string{
		"SOAP 1.1":                     strings.ReplaceAll(base, soapNS, "http://schemas.xmlsoap.org/soap/envelope/"),
		"wrong action":                 replace(DiscoveryAction, DiscoveryAction+"Response"),
		"different destination":        replace("enroll.example.test", "attacker.example.test"),
		"destination query":            replace("Discovery.svc</", "Discovery.svc?token=synthetic</"),
		"duplicate action":             replace("</a:Action>", "</a:Action><a:Action>ignored</a:Action>"),
		"wrong namespace action":       replace("<a:Action ", `<a:Action xmlns:a="urn:wrong" `),
		"nested action":                replace("</a:Action>", "<a:Nested/></a:Action>"),
		"nil UUID":                     replace(discoveryTestID, "urn:uuid:00000000-0000-0000-0000-000000000000"),
		"compact UUID":                 replace(discoveryTestID, "urn:uuid:d62c672009894a51a1b6103491d8eca4"),
		"missing message ID":           replace("<a:MessageID>"+discoveryTestID+"</a:MessageID>", ""),
		"external reply":               replace(addressingNS+"/anonymous", "https://attacker.example.test/"),
		"duplicate reply":              replace("</a:ReplyTo>", "</a:ReplyTo><a:ReplyTo/>"),
		"header after body":            replace("<s:Header>", "<s:Body>"),
		"second body child":            replace("</s:Body>", "<Other/></s:Body>"),
		"wrong body namespace":         replace(EnrollmentNamespace+`/"`, "urn:wrong\""),
		"body mixed text":              replace("</s:Body>", "secret-marker</s:Body>"),
		"non XML whitespace":           replace("</s:Body>", "\u00a0</s:Body>"),
		"null request":                 replace("<request xmlns:i=", `<request i:nil="true" xmlns:i=`),
		"unknown request attribute":    replace("<request xmlns:i=", `<request extra="secret-marker" xmlns:i=`),
		"unknown field":                replace("</EmailAddress>", "</EmailAddress><Organization>admin</Organization>"),
		"duplicate field":              replace("<OSEdition>48</OSEdition>", "<EmailAddress>other@example.test</EmailAddress>"),
		"namespace lookalike field":    replace("<OSEdition>", `<OSEdition xmlns="urn:wrong">`),
		"nested field":                 replace("</EmailAddress>", "<Nested/></EmailAddress>"),
		"field attribute":              replace("<EmailAddress>", `<EmailAddress role="admin">`),
		"control in email":             replace("synthetic@example.test", "synthetic&#10;@example.test"),
		"long email":                   replace("synthetic@example.test", strings.Repeat("x", 321)),
		"negative OS":                  replace(">48<", ">-1<"),
		"OS overflow":                  replace(">48<", ">4294967296<"),
		"OS hexadecimal":               replace(">48<", ">0x30<"),
		"unknown device":               replace("CIMClient_Windows", "administrator"),
		"partial application version":  replace("10.0.26100.1", "10.0.26100"),
		"application version overflow": replace("10.0.26100.1", "10.0.4294967296.1"),
		"application version exponent": replace("10.0.26100.1", "1e1.0.1.0"),
		"no auth policies":             replace("<AuthPolicy>OnPremise</AuthPolicy><AuthPolicy>Federated</AuthPolicy><AuthPolicy>Certificate</AuthPolicy>", ""),
		"duplicate auth policy":        replace("<AuthPolicy>Federated</AuthPolicy>", "<AuthPolicy>OnPremise</AuthPolicy>"),
		"unknown auth policy":          replace("<AuthPolicy>Federated</AuthPolicy>", "<AuthPolicy>Basic</AuthPolicy>"),
		"nil auth policies":            replace("<AuthPolicies>", `<AuthPolicies i:nil="true">`),
		"namespace lookalike policy":   replace("<AuthPolicy>Federated", `<AuthPolicy xmlns="urn:wrong">Federated`),
		"invalid mustUnderstand":       replace(`s:mustUnderstand="1"`, `s:mustUnderstand="yes"`),
		"unknown required header":      replace("</s:Header>", `<x:Required xmlns:x="urn:example" s:mustUnderstand="true"/></s:Header>`),
		"foreign SOAP role":            replace(`s:mustUnderstand="1"`, `s:role="urn:other"`),
		"oversized":                    base + strings.Repeat(" ", MaxDiscoveryBytes),
	}
	for _, version := range []string{"0", "10", "1.5", "-3.0", "3e0", "++3", "3..0", "3.00000000000000000", "NaN"} {
		cases["invalid version "+version] = replace(">5.0<", ">"+version+"<")
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			request, err := ParseDiscovery([]byte(wire), discoveryTestURL)
			if err == nil || request != nil {
				t.Fatal("malformed request was admitted")
			}
			if !errors.Is(err, ErrXML) && !errors.Is(err, ErrSOAP) && !errors.Is(err, ErrEndpoint) && !errors.Is(err, ErrDiscovery) && !errors.Is(err, ErrDiscoveryVersion) && !errors.Is(err, ErrDiscoveryPolicy) && !errors.Is(err, ErrMustUnderstand) {
				t.Fatal("error was not a fixed protocol error")
			}
		})
	}
}

func discoveryTestOptions() DiscoveryOptions {
	return DiscoveryOptions{AuthPolicy: "OnPremise", EnrollmentVersion: 3,
		EnrollmentPolicyURL: "https://enroll.example.test/EnrollmentServer/Policy.svc",
		EnrollmentURL:       "https://enroll.example.test/EnrollmentServer/Enrollment.svc"}
}

// Decode independently with the standard XML namespace resolver, so response
// tests do not merely demonstrate agreement with our own request parser.
func TestDiscoveryResponseWire(t *testing.T) {
	request, err := ParseDiscovery([]byte(discoveryTestMessage()), discoveryTestURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range request.AuthPolicies {
		t.Run(policy, func(t *testing.T) {
			options := discoveryTestOptions()
			options.AuthPolicy = policy
			if policy == "Federated" {
				options.AuthenticationURL = "https://auth.example.test/windows"
			}
			request.MessageID = "urn:uuid: D62C6720-0989-4A51-A1B6-103491D8ECA4"
			wire, err := BuildDiscoveryResponse(request, options)
			if err != nil {
				t.Fatal(err)
			}
			var response struct {
				XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"`
				Header  struct {
					Action    string `xml:"http://www.w3.org/2005/08/addressing Action"`
					RelatesTo string `xml:"http://www.w3.org/2005/08/addressing RelatesTo"`
				} `xml:"http://www.w3.org/2003/05/soap-envelope Header"`
				Body struct {
					Response struct {
						Result struct {
							Policy        string `xml:"http://schemas.microsoft.com/windows/management/2012/01/enrollment AuthPolicy"`
							Version       string `xml:"http://schemas.microsoft.com/windows/management/2012/01/enrollment EnrollmentVersion"`
							PolicyURL     string `xml:"http://schemas.microsoft.com/windows/management/2012/01/enrollment EnrollmentPolicyServiceUrl"`
							EnrollmentURL string `xml:"http://schemas.microsoft.com/windows/management/2012/01/enrollment EnrollmentServiceUrl"`
							AuthURL       string `xml:"http://schemas.microsoft.com/windows/management/2012/01/enrollment AuthenticationServiceUrl"`
						} `xml:"http://schemas.microsoft.com/windows/management/2012/01/enrollment DiscoverResult"`
					} `xml:"http://schemas.microsoft.com/windows/management/2012/01/enrollment DiscoverResponse"`
				} `xml:"http://www.w3.org/2003/05/soap-envelope Body"`
			}
			if err := xml.Unmarshal(wire, &response); err != nil {
				t.Fatal(err)
			}
			r := response.Body.Response.Result
			if response.Header.Action != DiscoveryResponseAction || response.Header.RelatesTo != request.MessageID || r.Policy != policy || r.Version != "3.0" || r.PolicyURL != options.EnrollmentPolicyURL || r.EnrollmentURL != options.EnrollmentURL || r.AuthURL != options.AuthenticationURL {
				t.Fatal("wire response has incorrect namespaces, correlation or configured endpoints")
			}
			if strings.Contains(string(wire), "synthetic@example.test") || strings.Contains(string(wire), "OSEdition") || strings.Contains(string(wire), "DeviceAssociationMaaUrl") || strings.Contains(string(wire), "GatewayService") {
				t.Fatal("response disclosed device hints or advertised unattested capabilities")
			}
		})
	}
}

func TestDiscoveryResponseRejectsInvalidConfiguration(t *testing.T) {
	request, err := ParseDiscovery([]byte(discoveryTestMessage()), discoveryTestURL)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*DiscoveryOptions){
		"insecure enrollment":                func(o *DiscoveryOptions) { o.EnrollmentURL = "http://enroll.example.test/enroll" },
		"missing policy endpoint":            func(o *DiscoveryOptions) { o.EnrollmentPolicyURL = "" },
		"unsupported policy":                 func(o *DiscoveryOptions) { o.AuthPolicy = "Basic" },
		"federated endpoint missing":         func(o *DiscoveryOptions) { o.AuthPolicy = "Federated" },
		"unexpected authentication endpoint": func(o *DiscoveryOptions) { o.AuthenticationURL = "https://auth.example.test/login" },
		"too old server version":             func(o *DiscoveryOptions) { o.EnrollmentVersion = 2 },
		"newer than client":                  func(o *DiscoveryOptions) { o.EnrollmentVersion = 6 },
	} {
		t.Run(name, func(t *testing.T) {
			o := discoveryTestOptions()
			change(&o)
			if wire, err := BuildDiscoveryResponse(request, o); err == nil || wire != nil {
				t.Fatal("invalid configuration admitted")
			}
		})
	}
	for _, r := range []*DiscoveryRequest{nil, {}, {MessageID: discoveryTestID, RequestVersion: 1, AuthPolicies: []string{"OnPremise"}}, {MessageID: discoveryTestID, RequestVersion: 3, AuthPolicies: []string{"Certificate"}}} {
		if wire, err := BuildDiscoveryResponse(r, discoveryTestOptions()); err == nil || wire != nil {
			t.Fatal("invalid request admitted")
		}
	}
}

func FuzzDiscovery(f *testing.F) {
	f.Add([]byte(discoveryTestMessage()))
	f.Add([]byte(`<root/>`))
	f.Fuzz(func(t *testing.T, wire []byte) {
		request, err := ParseDiscovery(wire, discoveryTestURL)
		if err != nil {
			if request != nil {
				t.Fatal("partial request returned with an error")
			}
			return
		}
		if request == nil || request.RequestVersion < 1 || request.RequestVersion > 9 || len(request.AuthPolicies) == 0 {
			t.Fatal("admitted request violated bounds")
		}
	})
}
