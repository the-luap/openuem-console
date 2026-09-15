package windows

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestXMLNamespaceResolution(t *testing.T) {
	wire := `<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<root xmlns="urn:root" xmlns:a="urn:one" plain="x" a:id="1">
  <a:child xmlns:a="urn:two" xml:lang="en"><leaf xmlns="">&lt;synthetic&gt;</leaf></a:child>
  <a:child><![CDATA[untouched & text]]><!-- comment --></a:child>
</root>`
	root, err := parseXML([]byte(wire), len(wire))
	if err != nil {
		t.Fatal(err)
	}
	if !root.is("urn:root", "root") || !root.container() || len(root.Attrs) != 2 || root.Attrs[0].Name != (xml.Name{Local: "plain"}) || root.Attrs[1].Name != (xml.Name{Space: "urn:one", Local: "id"}) {
		t.Fatal("default namespaces changed unprefixed attributes or root content")
	}
	first, second := root.Children[0], root.Children[1]
	if !first.is("urn:two", "child") || first.Attrs[0].Name.Space != xmlNS || !first.Children[0].is("", "leaf") || first.Children[0].Text != "<synthetic>" || !second.is("urn:one", "child") || second.Text != "untouched & text" {
		t.Fatal("namespace scoping or decoded text changed")
	}
}

func TestXMLRejectsAmbiguityAndExpansion(t *testing.T) {
	cases := map[string]string{
		"outside whitespace entity": "&#32;<r/>",
		"outside whitespace CDATA":  "<r/><![CDATA[ ]]>",
		"empty":                     "", "unclosed": "<r>", "extra root": "<r/><r/>", "outside text": "secret-marker<r/>",
		"outside non XML whitespace": "\u00a0<r/>", "trailing text": "<r/>secret-marker",
		"invalid UTF-8": "<r>\xff</r>", "null": "<r>\x00</r>", "invalid character entity": "<r>&#0;</r>",
		"unbound element": "<a:r/>", "unbound attribute": `<r a:id="1"/>`,
		"duplicate unprefixed attributes": `<r id="1" id="2"/>`,
		"duplicate expanded attributes":   `<r xmlns:a="urn:x" xmlns:b="urn:x" a:id="1" b:id="2"/>`,
		"duplicate namespace":             `<r xmlns:a="urn:x" xmlns:a="urn:y"/>`,
		"duplicate default namespace":     `<r xmlns="urn:x" xmlns="urn:y"/>`,
		"XML prefix rebound":              `<r xmlns:xml="urn:x"/>`,
		"XML URI aliased":                 `<r xmlns:a="` + xmlNS + `"/>`,
		"XMLNS prefix rebound":            `<r xmlns:xmlns="urn:x"/>`,
		"XMLNS URI bound":                 `<r xmlns:a="` + xmlnsNS + `"/>`,
		"empty prefix namespace":          `<r xmlns:a=""/>`,
		"invalid element QName":           `<a:r:x xmlns:a="urn:x"/>`,
		"leading colon":                   `<:r/>`, "trailing colon": `<r:/>`,
		"digit local part":                 `<a:1 xmlns:a="urn:x"/>`,
		"digit namespace prefix":           `<r xmlns:1="urn:x"/>`,
		"combining local start":            "<a:\u0301 xmlns:a=\"urn:x\"/>",
		"equivalent but different raw end": `<a:r xmlns:a="urn:x" xmlns:b="urn:x"></b:r>`,
		"mismatched end":                   "<r><a></r></a>",
		"DTD":                              `<!DOCTYPE r [<!ENTITY x "secret-marker">]><r>&x;</r>`,
		"external entity":                  `<!DOCTYPE r SYSTEM "https://never-contact.example.test/secret-marker"><r/>`,
		"unknown entity":                   `<r>&secret-marker;</r>`,
		"processing instruction":           `<?stylesheet href="secret-marker"?><r/>`,
		"duplicate declaration":            `<?xml version="1.0"?><?xml version="1.0"?><r/>`,
		"late declaration":                 `<r/><?xml version="1.0"?>`,
		"declaration after comment":        `<!--comment--><?xml version="1.0"?><r/>`,
		"declaration after whitespace":     ` <?xml version="1.0"?><r/>`,
		"empty declaration":                `<?xml?><r/>`,
		"malformed declaration":            `<?xml version="1.0" extra="secret-marker"?><r/>`,
		"duplicate declaration attribute":  `<?xml version="1.0" version="1.0"?><r/>`,
		"bad standalone":                   `<?xml version="1.0" standalone="true"?><r/>`,
		"other encoding":                   `<?xml version="1.0" encoding="UTF-16"?><r/>`,
		"other XML version":                `<?xml version="1.1"?><r/>`,
		"case insensitive XML target":      `<?XML version="1.0"?><r/>`,
		"invalid comment":                  `<r><!-- a -- b --></r>`,
		"depth limit":                      strings.Repeat("<r>", 33) + strings.Repeat("</r>", 33),
		"node limit":                       "<r>" + strings.Repeat("<a/>", 4096) + "</r>",
	}
	attrs, namespaceTree := "", ""
	for i := 0; i < 33; i++ {
		attrs += fmt.Sprintf(` a%d="x"`, i)
	}
	cases["attribute limit"] = "<r" + attrs + "/>"
	for level := 0; level < 3; level++ {
		namespaceTree += "<r"
		for i := 0; i < 22; i++ {
			namespaceTree += fmt.Sprintf(` xmlns:p%d="urn:x"`, level*22+i)
		}
		namespaceTree += ">"
	}
	cases["namespace context limit"] = namespaceTree + "</r></r></r>"
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			root, err := parseXML([]byte(wire), MaxDiscoveryBytes)
			if !errors.Is(err, ErrXML) || root != nil {
				t.Fatal("ambiguous or unsafe XML was admitted")
			}
		})
	}
	for _, maximum := range []int{-1, 0, 3} {
		if root, err := parseXML([]byte("<r/>"), maximum); err != ErrXML || root != nil {
			t.Fatal("invalid byte limit admitted")
		}
	}
}

func TestEnrollmentEndpointBinding(t *testing.T) {
	for _, value := range []string{
		"http://enroll.example.test/EnrollmentServer/Discovery.svc",
		"https://attacker.example.test/EnrollmentServer/Discovery.svc",
		"https://enroll.example.test:444/EnrollmentServer/Discovery.svc",
		"https://enroll.example.test/EnrollmentServer/discovery.svc",
		"https://enroll.example.test/EnrollmentServer/../EnrollmentServer/Discovery.svc",
		"https://enroll.example.test//EnrollmentServer/Discovery.svc",
		"https://enroll.example.test/EnrollmentServer/%44iscovery.svc",
		"https://enroll.example.test/EnrollmentServer/Discovery.svc?",
		"https://enroll.example.test/EnrollmentServer/Discovery.svc#fragment",
		"https://user:secret-marker@enroll.example.test/EnrollmentServer/Discovery.svc",
	} {
		if sameEnrollmentEndpoint(value, discoveryTestURL) {
			t.Fatal("different endpoint was admitted")
		}
	}
	for _, value := range []string{
		"", "https:opaque", "https://example.test", "https://example.test:/path", "https://example.test:0/path", "https://example.test:65536/path",
		"https://[example.test]/path", "https://[127.0.0.1]/path",
		"https://example.test/path%20space", "https://example.test/path\\other", "https://example.test/path%0aother", "https://example.test/path%25other",
		"https://-bad.example.test/path", "https://bad_.example.test/path", "https://a..example.test/path", "https://[fe80::1%25eth0]/path", "https://😀.example.test/path",
	} {
		if _, err := enrollmentEndpoint(value); err != ErrEndpoint {
			t.Fatal("invalid configured URL admitted")
		}
	}
	for _, value := range []string{discoveryTestURL, "https://[::1]:8443/enroll", "https://127.0.0.1:8443/enroll", "https://xn--bcher-kva.example.test/enroll"} {
		if _, err := enrollmentEndpoint(value); err != nil {
			t.Fatal(err)
		}
	}
}
