package apple

import (
	"strings"
	"testing"

	"howett.net/plist"
)

func TestExtensibleSSORoutingUniqueness(t *testing.T) {
	payload := func(kind, field string, values ...any) map[string]any {
		return map[string]any{"PayloadType": "com.apple.extensiblesso", "Type": kind, field: values}
	}
	redirect := func(values ...any) map[string]any { return payload("Redirect", "URLs", values...) }
	credential := func(values ...any) map[string]any { return payload("Credential", "Hosts", values...) }
	cases := []struct {
		name    string
		items   []any
		want    int
		invalid bool
	}{
		{name: "ordinary profile", items: []any{map[string]any{"PayloadType": "com.apple.wifi.managed"}}, want: 0},
		{name: "multiple providers", items: []any{redirect("https://one.example.test/"), redirect("https://two.example.test/")}, want: 2},
		{name: "URL scheme and host folding", items: []any{redirect("https://login.example.test/"), redirect("HTTPS://LOGIN.example.test/")}, invalid: true},
		{name: "case-sensitive paths", items: []any{redirect("https://login.example.test/Account"), redirect("https://login.example.test/account")}, want: 2},
		{name: "distinct prefixes allowed", items: []any{redirect("https://login.example.test/"), redirect("https://login.example.test/account")}, want: 2},
		{name: "different schemes", items: []any{redirect("http://login.example.test/"), redirect("https://login.example.test/")}, want: 2},
		{name: "duplicates within one payload", items: []any{redirect("https://login.example.test/", "https://LOGIN.example.test/")}, invalid: true},
		{name: "credential folding", items: []any{credential(".example.test"), credential(".EXAMPLE.test")}, invalid: true},
		{name: "distinct wildcard and exact hosts", items: []any{credential(".example.test", "login.example.test", "example.test")}, want: 3},
		{name: "hosts and URLs use separate namespaces", items: []any{credential("login.example.test"), redirect("https://login.example.test/")}, want: 2},
		{name: "missing redirect URLs", items: []any{payload("Redirect", "Hosts", "login.example.test")}, invalid: true},
		{name: "missing credential hosts", items: []any{payload("Credential", "URLs", "https://login.example.test/")}, invalid: true},
		{name: "unknown routing type", items: []any{payload("Other", "URLs", "https://login.example.test/")}, invalid: true},
		{name: "non-string route", items: []any{redirect(true)}, invalid: true},
	}
	for _, raw := range []string{"https://login.example.test/?", "https://login.example.test/#", "https://user:pass@login.example.test/", "file:///login", "https://login.example.test/\n", strings.Repeat("x", 2049)} {
		cases = append(cases, struct {
			name    string
			items   []any
			want    int
			invalid bool
		}{"invalid URL", []any{redirect(raw)}, 0, true})
	}
	for _, raw := range []string{"", ".", "..", "*.example.test", "https://example.test/", "example.test:443", "a b", "a\nb", "a..b", "user@example.test", "[::1]", strings.Repeat("x", 2049)} {
		cases = append(cases, struct {
			name    string
			items   []any
			want    int
			invalid bool
		}{"invalid host", []any{credential(raw)}, 0, true})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := plist.Marshal(map[string]any{"PayloadContent": tc.items}, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := extensibleSSORoutes(data)
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid or duplicate routing accepted")
				}
				return
			}
			if err != nil || len(keys) != tc.want {
				t.Fatalf("route count=%d want=%d: %v", len(keys), tc.want, err)
			}
		})
	}
}

func TestExtensibleSSORoutingIgnoresInapplicableFields(t *testing.T) {
	for _, p := range []map[string]any{
		{"PayloadType": "com.apple.extensiblesso", "Type": "Credential", "Hosts": []any{"example.test"}, "URLs": []any{true}},
		{"PayloadType": "com.apple.extensiblesso", "Type": "Redirect", "URLs": []any{"https://example.test/"}, "Hosts": []any{true}},
	} {
		keys, err := extensibleSSORootRoutes(map[string]any{"PayloadContent": []any{p}})
		if err != nil || len(keys) != 1 {
			t.Fatal("ignored SSO field changed routing validation", err)
		}
	}
}
