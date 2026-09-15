package apple

import "testing"

func FuzzVendorPlist(f *testing.F) {
	f.Add([]byte(`<plist version="1.0"><dict><key>PushCertRequestCSR</key><string>A</string><key>PushCertCertificateChain</key><string>B</string><key>PushCertSignature</key><string>C</string></dict></plist>`))
	f.Add([]byte(`<plist version="1.0"><dict><key>PushCertRequestCSR</key><string>&external;</string></dict></plist>`))
	f.Add([]byte(`<plist xmlns="urn:foreign" version="1.0"><dict/></plist>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxVendorPortalRequest {
			t.Skip()
		}
		fields, err := parseVendorPlist(data)
		if err == nil && (len(fields) != 3 || fields["PushCertRequestCSR"] == "" || fields["PushCertCertificateChain"] == "" || fields["PushCertSignature"] == "") {
			t.Fatal("parser returned an incomplete request without an error")
		}
	})
}
