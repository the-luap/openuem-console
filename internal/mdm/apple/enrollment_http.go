package apple

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

//go:embed enrollment_page.html
var enrollmentHTML string

//go:embed enrollment_page.css
var enrollmentCSS string

var enrollmentTemplate = template.Must(template.New("enrollment").Parse(enrollmentHTML))

type enrollmentPageData struct {
	*EnrollmentStatus
	Path, CSRF, Error string
	CSS               template.CSS
}

func renderEnrollmentPage(w http.ResponseWriter, r *http.Request, code int, data enrollmentPageData) {
	if data.EnrollmentStatus == nil {
		data.EnrollmentStatus = &EnrollmentStatus{State: "unavailable"}
	}
	data.CSS = template.CSS(enrollmentCSS) // Embedded source, never user input.
	styleHash := sha256.Sum256([]byte(enrollmentCSS))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'sha256-"+base64.StdEncoding.EncodeToString(styleHash[:])+"'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var body bytes.Buffer
	if err := enrollmentTemplate.Execute(&body, data); err != nil {
		http.Error(w, "Enrollment is temporarily unavailable. Try again later.", 503)
		return
	}
	w.WriteHeader(code)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body.Bytes())
	}
}

func enrollmentBrowser(r *http.Request) string {
	cookies := r.CookiesNamed(enrollmentBrowserCookie)
	if len(cookies) != 1 || !validEnrollmentToken(cookies[0].Value) {
		return ""
	}
	return cookies[0].Value
}

func setEnrollmentBrowser(w http.ResponseWriter, browser string) {
	http.SetCookie(w, &http.Cookie{Name: enrollmentBrowserCookie, Value: browser, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 3600})
}

func (s *Store) enrollmentPage(w http.ResponseWriter, r *http.Request, token string, limits *enrollmentLimiter, identity clientidentity.Policy) {
	page := enrollmentPageData{Path: r.URL.Path}
	fail := func(code int, message string) {
		page.Error = message
		renderEnrollmentPage(w, r, code, page)
	}
	if r.TLS == nil || !r.TLS.HandshakeComplete {
		fail(400, "Open the secure HTTPS invitation supplied by your administrator.")
		return
	}
	if !validEnrollmentToken(token) || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(404, "This invitation is unavailable. Ask your administrator for a new link.")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, HEAD, POST")
		fail(405, "Open this invitation in your browser to continue.")
		return
	}
	if !limits.allow(r, identity) {
		w.Header().Set("Retry-After", "30")
		fail(429, "Too many enrollment requests. Wait 30 seconds and try again.")
		return
	}
	browser := enrollmentBrowser(r)
	if browser == "" && r.Method != http.MethodPost {
		var err error
		browser, err = randomToken()
		if err != nil {
			fail(503, "Enrollment is temporarily unavailable. Try again later.")
			return
		}
		setEnrollmentBrowser(w, browser)
	}
	status, err := s.EnrollmentStatus(r.Context(), token, browser)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			fail(404, "This invitation is unavailable or was revoked. Ask your administrator for a new link.")
		} else {
			fail(503, "Enrollment is temporarily unavailable. Keep this page and try again later.")
		}
		return
	}
	page.EnrollmentStatus, page.CSRF = status, enrollmentCSRF(token, browser)
	if r.Method != http.MethodPost {
		renderEnrollmentPage(w, r, 200, page)
		return
	}
	origin, err := url.Parse(status.PublicOrigin)
	if err != nil || origin.Scheme != "https" || !strings.EqualFold(origin.Host, r.Host) || len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != strings.TrimRight(status.PublicOrigin, "/") || (r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") || browser == "" {
		fail(403, "Open the original invitation in this browser before continuing.")
		return
	}
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/x-www-form-urlencoded" {
		fail(415, "Use the enrollment form on this page.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err = r.ParseForm(); err != nil {
		fail(400, "The enrollment form could not be read. Reload this page and try again.")
		return
	}
	if len(r.PostForm["csrf"]) != 1 || !hmac.Equal([]byte(r.PostForm.Get("csrf")), []byte(page.CSRF)) {
		fail(403, "The enrollment form expired. Reload this page and try again.")
		return
	}
	switch r.PostForm.Get("action") {
	case "claim":
		if len(r.PostForm["platform"]) != 1 || r.PostForm.Get("confirm") != "yes" || (r.PostForm.Get("platform") != "ios" && r.PostForm.Get("platform") != "ipados" && r.PostForm.Get("platform") != "macos") {
			fail(400, "Select iPhone, iPad or Mac and confirm device management. Other platforms cannot use this invitation.")
			return
		}
		select {
		case limits.claims <- struct{}{}:
			defer func() { <-limits.claims }()
		default:
			w.Header().Set("Retry-After", "10")
			fail(429, "Enrollment is busy. Wait 10 seconds and try again.")
			return
		}
		if err = s.ClaimEnrollment(r.Context(), token, browser, Platform(r.PostForm.Get("platform"))); err == nil {
			// Starting near the invitation deadline must still leave the browser
			// its bounded download/status window. This does not extend DB expiry.
			setEnrollmentBrowser(w, browser)
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}
	case "download":
		var profile []byte
		profile, err = s.DownloadEnrollment(r.Context(), token, browser)
		if err == nil {
			w.Header().Set("Content-Type", "application/x-apple-aspen-config")
			w.Header().Set("Content-Disposition", `attachment; filename="OpenUEM.mobileconfig"`)
			_, _ = w.Write(profile)
			return
		}
	default:
		fail(400, "Choose an action from the enrollment page.")
		return
	}
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) || errors.Is(err, ErrUnauthorized) {
		// Reload state so stale forms cannot offer another download after success.
		if latest, stateErr := s.EnrollmentStatus(r.Context(), token, browser); stateErr == nil {
			page.EnrollmentStatus = latest
		}
		fail(409, "This action is no longer available. Check enrollment status below. If setup cannot continue, ask your administrator to revoke this invitation and issue a new one.")
	} else {
		fail(503, "Enrollment is temporarily unavailable. Keep this page and try again later.")
	}
}
