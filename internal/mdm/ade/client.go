package ade

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const serviceOrigin = "https://mdmenrollment.apple.com"
const PageLimit = 1000
const maxResponse = 4 << 20

var (
	ErrService       = errors.New("Automated Device Enrollment service is unavailable")
	ErrAuthorization = errors.New("Automated Device Enrollment credentials were rejected")
	ErrCursor        = errors.New("Automated Device Enrollment synchronization cursor expired")
)

// RetryError contains scheduling information only, never Apple's response body,
// authentication headers or request URL. Callers persist this deadline.
type RetryError struct{ After time.Duration }

func (*RetryError) Error() string {
	return "Automated Device Enrollment service requested a later retry"
}

type Account struct {
	ServerID         string `json:"server_uuid"`
	ServerName       string `json:"server_name"`
	OrganizationID   string `json:"org_id"`
	OrganizationName string `json:"org_name"`
	OrganizationType string `json:"org_type"`
	Administrator    string `json:"admin_id"`
}

type Device struct {
	Serial        string    `json:"serial_number"`
	Model         string    `json:"model"`
	OS            string    `json:"os"`
	Family        string    `json:"device_family"`
	ProfileStatus string    `json:"profile_status"`
	ProfileID     string    `json:"profile_uuid"`
	Operation     string    `json:"op_type"`
	OperationAt   time.Time `json:"op_date,omitempty"`
}

type Page struct {
	Devices []Device
	Cursor  string
	More    bool
}

type Service interface {
	Account(context.Context) (Account, error)
	Devices(context.Context, string, bool) (Page, error)
	Close()
}

type Client struct {
	mu      sync.Mutex
	token   tokenData
	session string
	origin  string
	http    *http.Client
}

func (*Client) String() string               { return "[private Automated Device Enrollment session]" }
func (c *Client) GoString() string           { return c.String() }
func (*Client) MarshalJSON() ([]byte, error) { return nil, ErrToken }

// NewClient fixes the production origin and forbids redirects. Each client owns
// a session and serializes header replacement. Close after the bounded operation.
func NewClient(token *Token) *Client {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 32 << 10, DisableCompression: true, ForceAttemptHTTP2: true, IdleConnTimeout: 30 * time.Second}
	c := &Client{origin: serviceOrigin, http: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if token != nil {
		c.token = token.data
	}
	return c
}

func (c *Client) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = tokenData{}
	c.session = ""
	c.http.CloseIdleConnections()
}

func human(s string, max int) bool {
	return len(s) <= max && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

func (c *Client) Account(ctx context.Context) (Account, error) {
	var a Account
	err := c.request(ctx, "GET", "/account", nil, &a)
	if err != nil {
		return a, err
	}
	id, err := uuid.Parse(a.ServerID)
	if err != nil || id == uuid.Nil || !opaque(a.OrganizationID, 128) || a.ServerName == "" || !human(a.ServerName, 255) || !human(a.OrganizationName, 255) || !human(a.OrganizationType, 64) || !human(a.Administrator, 320) {
		return Account{}, ErrService
	}
	a.ServerID = id.String()
	return a, nil
}

func (c *Client) Devices(ctx context.Context, cursor string, delta bool) (Page, error) {
	if len(cursor) > 1000 || cursor != "" && !opaque(cursor, 1000) || delta && cursor == "" {
		return Page{}, ErrCursor
	}
	payload, _ := json.Marshal(struct {
		Limit  int    `json:"limit"`
		Cursor string `json:"cursor,omitempty"`
	}{PageLimit, cursor})
	path := "/server/devices"
	if delta {
		path = "/devices/sync"
	}
	var wire struct {
		Devices *[]Device `json:"devices"`
		Cursor  string    `json:"cursor"`
		More    *bool     `json:"more_to_follow"`
	}
	if err := c.request(ctx, "POST", path, payload, &wire); err != nil {
		return Page{}, err
	}
	if wire.More == nil || wire.Devices == nil || !opaque(wire.Cursor, 1000) || len(*wire.Devices) > PageLimit {
		return Page{}, ErrService
	}
	if *wire.More && wire.Cursor == cursor {
		return Page{}, ErrCursor
	}
	for i := range *wire.Devices {
		d := &(*wire.Devices)[i]
		if !ValidSerial(d.Serial) || !human(d.Model, 255) || !human(d.OS, 64) || !human(d.Family, 64) || !human(d.ProfileStatus, 64) || !human(d.ProfileID, 128) {
			return Page{}, ErrService
		}
		if delta {
			if (d.Operation != "added" && d.Operation != "modified" && d.Operation != "deleted") || d.OperationAt.IsZero() || d.OperationAt.After(time.Now().Add(5*time.Minute)) {
				return Page{}, ErrService
			}
		} else if d.Operation != "" {
			return Page{}, ErrService
		}
	}
	return Page{Devices: *wire.Devices, Cursor: wire.Cursor, More: *wire.More}, nil
}

func ValidSerial(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func (c *Client) request(ctx context.Context, method, path string, body []byte, out any) error {
	if c == nil || ctx == nil {
		return ErrService
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if !c.token.Expiry.After(time.Now().Add(time.Minute)) {
			return ErrToken
		}
		if c.session == "" {
			var session struct {
				Token string `json:"auth_session_token"`
			}
			if err := c.exchange(ctx, "GET", "/session", nil, &session, true); err != nil {
				return err
			}
			if !opaque(session.Token, 8192) {
				return ErrService
			}
			c.session = session.Token
		}
		err := c.exchange(ctx, method, path, body, out, false)
		if !errors.Is(err, ErrAuthorization) {
			return err
		}
		c.session = ""
	}
	return ErrAuthorization
}

func (c *Client) exchange(ctx context.Context, method, path string, body []byte, out any, session bool) error {
	request, err := http.NewRequestWithContext(ctx, method, c.origin+path, bytes.NewReader(body))
	if err != nil {
		return ErrService
	}
	request.Header.Set("User-Agent", "OpenUEM/1.0")
	request.Header.Set("X-Server-Protocol-Version", "10")
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if session {
		nonce := make([]byte, 24)
		if _, err = rand.Read(nonce); err != nil {
			return ErrService
		}
		request.Header.Set("Authorization", oauthHeader(method, request.URL, c.token, time.Now(), hex.EncodeToString(nonce)))
	} else {
		request.Header.Set("X-ADM-Auth-Session", c.session)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return ErrService
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return ErrAuthorization
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
		after := time.Minute
		if seconds, err := strconv.ParseUint(response.Header.Get("Retry-After"), 10, 64); err == nil {
			after = time.Duration(min(seconds, uint64((1<<63-1)/int64(time.Second)))) * time.Second
		} else if date, err := http.ParseTime(response.Header.Get("Retry-After")); err == nil {
			after = time.Until(date)
		}
		after = max(time.Second, after)
		return &RetryError{After: after}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil || len(data) > maxResponse {
		return ErrService
	}
	defer clear(data)
	if response.StatusCode != http.StatusOK {
		code := strings.TrimSpace(string(data))
		var failure struct {
			Code string `json:"error_code"`
		}
		if decodeJSON(data, &failure) == nil {
			code = failure.Code
		}
		if response.StatusCode == http.StatusBadRequest && (path == "/devices/sync" || path == "/server/devices") {
			switch code {
			case "EXPIRED_CURSOR", "INVALID_CURSOR", "EXHAUSTED_CURSOR", "CURSOR_REQUIRED":
				return ErrCursor
			}
		}
		return ErrService
	}
	if decodeJSON(data, out) != nil {
		return ErrService
	}
	if replacement := response.Header.Get("X-ADM-Auth-Session"); replacement != "" {
		if !opaque(replacement, 8192) {
			return ErrService
		}
		c.session = replacement
	}
	return nil
}

func oauthEscape(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }

// OAuth 1.0 uses HMAC-SHA1 here because Apple's session protocol requires it.
// JSON request bodies are not OAuth form parameters (RFC 5849, section 3.4.1.3).
func oauthHeader(method string, u *url.URL, t tokenData, now time.Time, nonce string) string {
	params := url.Values{"oauth_consumer_key": {t.ConsumerKey}, "oauth_token": {t.AccessToken}, "oauth_signature_method": {"HMAC-SHA1"}, "oauth_timestamp": {strconv.FormatInt(now.Unix(), 10)}, "oauth_nonce": {nonce}, "oauth_version": {"1.0"}}
	var pairs []string
	for k, values := range u.Query() {
		for _, v := range values {
			pairs = append(pairs, oauthEscape(k)+"="+oauthEscape(v))
		}
	}
	for k, values := range params {
		pairs = append(pairs, oauthEscape(k)+"="+oauthEscape(values[0]))
	}
	sort.Strings(pairs)
	baseURL := u.Scheme + "://" + u.Host + u.EscapedPath()
	if u.EscapedPath() == "" {
		baseURL += "/"
	}
	base := method + "&" + oauthEscape(baseURL) + "&" + oauthEscape(strings.Join(pairs, "&"))
	mac := hmac.New(sha1.New, []byte(oauthEscape(t.ConsumerSecret)+"&"+oauthEscape(t.AccessSecret)))
	mac.Write([]byte(base))
	params.Set("oauth_signature", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	pairs = nil
	for k, v := range params {
		pairs = append(pairs, oauthEscape(k)+`="`+oauthEscape(v[0])+`"`)
	}
	sort.Strings(pairs)
	return "OAuth " + strings.Join(pairs, ", ")
}
