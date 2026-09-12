package windows

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func discoveryTLSServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	base := "https://" + server.Listener.Addr().String()
	options := discoveryTestOptions()
	options.EnrollmentPolicyURL = base + "/EnrollmentServer/Policy.svc"
	options.EnrollmentURL = base + "/EnrollmentServer/Enrollment.svc"
	handler, err := NewDiscoveryHandler(base+DiscoveryPath, options)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.Config.ReadHeaderTimeout = 2 * time.Second
	server.Config.ReadTimeout = 5 * time.Second
	server.Config.WriteTimeout = 5 * time.Second
	server.Config.MaxHeaderBytes = 16 << 10
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	server.Client().Timeout = 5 * time.Second
	return server, base
}

func TestDiscoveryHTTPS(t *testing.T) {
	server, base := discoveryTLSServer(t)
	wire := strings.ReplaceAll(discoveryTestMessage(), discoveryTestURL, base+DiscoveryPath)
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			request, err := http.NewRequest(method, base+DiscoveryPath, strings.NewReader(wire))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", mime.FormatMediaType("application/soap+xml", map[string]string{"charset": "utf-8", "action": DiscoveryAction}))
			request.Header.Set("Forwarded", `host=attacker.example.test;proto=http`)
			request.Header.Set("X-Forwarded-Host", "attacker.example.test")
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 || response.ProtoMajor != 1 || len(response.TransferEncoding) != 0 || response.ContentLength != int64(len(body)) || response.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
				t.Fatal("discovery did not return a complete, successful HTTP/1.1 message")
			}
			if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Set-Cookie") != "" {
				t.Fatal("unexpected cache or cookie behavior")
			}
			if method != http.MethodPost {
				if len(body) != 0 {
					t.Fatal("availability probe returned enrollment data")
				}
				return
			}
			media, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
			if err != nil || media != "application/soap+xml" || parameters["action"] != DiscoveryResponseAction {
				t.Fatal("incorrect SOAP response media type")
			}
			if !strings.Contains(string(body), base+"/EnrollmentServer/Enrollment.svc") || !strings.Contains(string(body), discoveryTestID) || strings.Contains(string(body), "attacker.example.test") {
				t.Fatal("response destination or correlation was changed")
			}
		})
	}
}

func TestDiscoveryHTTPRejectsRequests(t *testing.T) {
	server, base := discoveryTLSServer(t)
	wire := strings.ReplaceAll(discoveryTestMessage(), discoveryTestURL, base+DiscoveryPath)
	type rejection struct {
		status int
		edit   func(*http.Request)
	}
	cases := map[string]rejection{
		"wrong host": {404, func(r *http.Request) {
			r.Host = "attacker.example.test"
			r.Header.Set("X-Forwarded-Host", strings.TrimPrefix(base, "https://"))
		}},
		"wrong path case":          {404, func(r *http.Request) { r.URL.Path = "/enrollmentserver/Discovery.svc" }},
		"dot path":                 {404, func(r *http.Request) { r.URL.Path = "/EnrollmentServer/../EnrollmentServer/Discovery.svc" }},
		"encoded path":             {404, func(r *http.Request) { r.URL.RawPath = "/EnrollmentServer/%44iscovery.svc" }},
		"query string":             {404, func(r *http.Request) { r.URL.RawQuery = "account=synthetic@example.test" }},
		"empty query":              {404, func(r *http.Request) { r.URL.ForceQuery = true }},
		"wrong method":             {405, func(r *http.Request) { r.Method = http.MethodPut }},
		"missing content type":     {415, func(r *http.Request) { r.Header.Del("Content-Type") }},
		"SOAP 1.1 type":            {415, func(r *http.Request) { r.Header.Set("Content-Type", "text/xml") }},
		"duplicate content type":   {415, func(r *http.Request) { r.Header.Add("Content-Type", "application/soap+xml") }},
		"wrong HTTP action":        {415, func(r *http.Request) { r.Header.Set("Content-Type", `application/soap+xml; action="urn:wrong"`) }},
		"SOAPAction header":        {415, func(r *http.Request) { r.Header.Set("SOAPAction", `"urn:wrong"`) }},
		"wrong character encoding": {415, func(r *http.Request) { r.Header.Set("Content-Type", "application/soap+xml; charset=utf-16") }},
		"compressed request":       {415, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		"oversized length": {413, func(r *http.Request) {
			data := wire + strings.Repeat(" ", MaxDiscoveryBytes)
			r.Body = io.NopCloser(strings.NewReader(data))
			r.ContentLength = int64(len(data))
		}},
		"oversized chunked body": {413, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(wire + strings.Repeat(" ", MaxDiscoveryBytes)))
			r.ContentLength = -1
		}},
		"untrusted body endpoint": {400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(discoveryTestMessage()))
			r.ContentLength = -1
		}},
		"unoffered policy": {400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.ReplaceAll(wire, "<AuthPolicy>OnPremise</AuthPolicy>", "")))
			r.ContentLength = -1
		}},
		"newer server version": {400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.ReplaceAll(wire, ">5.0<", ">1.0<")))
			r.ContentLength = -1
		}},
		"malformed secret input": {400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("<synthetic-secret-marker>"))
			r.ContentLength = -1
		}},
		"unknown required SOAP header": {400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.ReplaceAll(wire, "</s:Header>", `<x:Unknown xmlns:x="urn:example" s:mustUnderstand="1"/></s:Header>`)))
			r.ContentLength = -1
		}},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodPost, base+DiscoveryPath, strings.NewReader(wire))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
			test.edit(r)
			response, err := server.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != test.status || response.ContentLength != int64(len(body)) || len(response.TransferEncoding) != 0 {
				t.Fatalf("status=%d, expected=%d, length=%d", response.StatusCode, test.status, response.ContentLength)
			}
			for _, secret := range []string{"synthetic-secret-marker", "synthetic@example.test", "attacker.example.test"} {
				if strings.Contains(string(body), secret) {
					t.Fatal("fault reflected request data")
				}
			}
			if test.status == 405 && response.Header.Get("Allow") != "GET, HEAD, POST" {
				t.Fatal("missing allowed methods")
			}
			if test.status == 400 {
				var fault struct {
					XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"`
					Body    struct {
						Fault struct {
							Code struct {
								Value string `xml:"http://www.w3.org/2003/05/soap-envelope Value"`
							} `xml:"http://www.w3.org/2003/05/soap-envelope Code"`
							Reason struct {
								Text struct {
									Language string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
									Value    string `xml:",chardata"`
								} `xml:"http://www.w3.org/2003/05/soap-envelope Text"`
							} `xml:"http://www.w3.org/2003/05/soap-envelope Reason"`
						} `xml:"http://www.w3.org/2003/05/soap-envelope Fault"`
					} `xml:"http://www.w3.org/2003/05/soap-envelope Body"`
				}
				if err := xml.Unmarshal(body, &fault); err != nil {
					t.Fatal(err)
				}
				code := "s:Sender"
				if name == "unknown required SOAP header" {
					code = "s:MustUnderstand"
				}
				if fault.Body.Fault.Code.Value != code || fault.Body.Fault.Reason.Text.Language != "en" || fault.Body.Fault.Reason.Text.Value == "" {
					t.Fatal("invalid SOAP fault namespace or code")
				}
			}
		})
	}
}

type discoveryCountingBody struct {
	io.Reader
	read   int
	closed bool
}

func (b *discoveryCountingBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}
func (b *discoveryCountingBody) Close() error { b.closed = true; return nil }

func TestDiscoveryBodyBoundAndTLSRequirement(t *testing.T) {
	h, err := NewDiscoveryHandler(discoveryTestURL, discoveryTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, tlsPresent := range []bool{false, true} {
		body := &discoveryCountingBody{Reader: strings.NewReader(strings.Repeat(" ", MaxDiscoveryBytes*4))}
		r := httptest.NewRequest(http.MethodPost, discoveryTestURL, body)
		r.Header.Set("Content-Type", "application/soap+xml")
		r.Header.Set("X-Forwarded-Proto", "https")
		if !tlsPresent {
			r.TLS = nil
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !tlsPresent {
			if w.Code != 400 || body.read != 0 {
				t.Fatal("forwarded header bypassed TLS requirement")
			}
		} else if w.Code != 413 || body.read != MaxDiscoveryBytes+1 || !body.closed {
			t.Fatal("unbounded request read or body not closed")
		}
	}
	wire := discoveryTestMessage()
	wire += strings.Repeat(" ", MaxDiscoveryBytes-len(wire))
	r := httptest.NewRequest(http.MethodPost, discoveryTestURL, strings.NewReader(wire))
	r.Header.Set("Content-Type", "application/soap+xml")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("exact byte boundary rejected")
	}
}

func TestDiscoveryConcurrentCorrelation(t *testing.T) {
	server, base := discoveryTLSServer(t)
	var wg sync.WaitGroup
	for i := 1; i <= 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("urn:uuid:d62c6720-0989-4a51-a1b6-%012d", i)
			wire := strings.NewReplacer(discoveryTestURL, base+DiscoveryPath, discoveryTestID, id).Replace(discoveryTestMessage())
			response, err := server.Client().Post(base+DiscoveryPath, "application/soap+xml", strings.NewReader(wire))
			if err != nil {
				t.Error(err)
				return
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != 200 || strings.Count(string(body), id) != 1 {
				t.Error("concurrent response correlation lost")
			}
		}(i)
	}
	wg.Wait()
}

func TestDiscoveryHandlerConfiguration(t *testing.T) {
	for _, url := range []string{"", "http://enroll.example.test" + DiscoveryPath, "https://enroll.example.test/wrong", discoveryTestURL + "?query"} {
		if h, err := NewDiscoveryHandler(url, discoveryTestOptions()); h != nil || err == nil {
			t.Fatal("invalid discovery URL admitted")
		}
	}
	o := discoveryTestOptions()
	o.EnrollmentPolicyURL = "https://other.example.test/policy"
	if h, err := NewDiscoveryHandler(discoveryTestURL, o); h != nil || err != ErrEndpoint {
		t.Fatal("policy and enrollment host mismatch admitted")
	}
	o = discoveryTestOptions()
	o.EnrollmentVersion = 10
	if h, err := NewDiscoveryHandler(discoveryTestURL, o); h != nil || err != ErrDiscoveryVersion {
		t.Fatal("unsupported service version admitted")
	}
}

type discoveryFailedReader struct{}

func (discoveryFailedReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic-private-read-error")
}

func TestDiscoveryReadFailurePrivacy(t *testing.T) {
	h, err := NewDiscoveryHandler(discoveryTestURL, discoveryTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []io.ReadCloser{nil, io.NopCloser(discoveryFailedReader{})} {
		r := httptest.NewRequest(http.MethodPost, discoveryTestURL, nil)
		r.Body = body
		r.Header.Set("Content-Type", "application/soap+xml")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 || strings.Contains(w.Body.String(), "synthetic-private-read-error") || !strings.Contains(w.Body.String(), "s:Sender") {
			t.Fatal("body failure did not produce a private sender fault")
		}
	}
}
