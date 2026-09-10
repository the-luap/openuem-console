package handlers

import "testing"

func TestWindowsCertificateHealthQueryIsBoundedAndCanonical(t *testing.T) {
	for _, raw := range []string{"filter=unknown", "filter=", "filter=all&filter=pending", "days=0", "days=366", "days=01", "days=", "days=+30", "offset=-1", "offset=100001", "offset=", "q=a&q=b", "q=%0A", "q=%FF", "q=%zz", "tenant=2", "filter=all;days=30"} {
		if _, err := windowsCertificateHealthOptions(raw, false); err == nil {
			t.Fatal("invalid filters accepted", raw)
		}
	}
	if _, err := windowsCertificateHealthOptions("", true); err == nil {
		t.Fatal("empty query marker accepted")
	}
	o, err := windowsCertificateHealthOptions("", false)
	if err != nil || o.Filter != "attention" || o.WithinDays != 30 || o.Offset != 0 || o.Limit != 26 {
		t.Fatal("default health view changed", err)
	}
	o, err = windowsCertificateHealthOptions("filter=pending&days=365&offset=100000&q=A%26B", false)
	if err != nil || o.Search != "A&B" || o.Filter != "pending" || o.WithinDays != 365 || o.Offset != 100000 {
		t.Fatal("valid health filters lost", err)
	}
}
