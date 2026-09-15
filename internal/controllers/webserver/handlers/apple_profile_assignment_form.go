package handlers

import (
	"crypto/subtle"
	"mime"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
)

func appleProfileAssignmentForm(c echo.Context) (int, []string, string, error) {
	failure := func(status int) (int, []string, string, error) {
		return 0, nil, "", echo.NewHTTPError(status, appleErrorText(c, "apple_errors.assignment_form"))
	}
	r := c.Request()
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" {
		return failure(http.StatusUnsupportedMediaType)
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return failure(http.StatusBadRequest)
	}
	const limit = 64 << 10 // Includes 1,000 repeated native device UUID fields.
	if r.ContentLength > limit {
		return failure(http.StatusRequestEntityTooLarge)
	}
	r.Body = http.MaxBytesReader(c.Response(), r.Body, limit)
	if err = r.ParseForm(); err != nil {
		return failure(http.StatusBadRequest)
	}
	f := r.PostForm
	if len(f.Encode()) > limit {
		return failure(http.StatusRequestEntityTooLarge)
	}
	for key, values := range f {
		if key == "device_id" {
			continue
		}
		if (key != "csrf" && key != "expected_revision" && key != "desired") || len(values) != 1 {
			return failure(http.StatusBadRequest)
		}
	}
	expected, _ := c.Get("csrf").(string)
	if len(f["csrf"]) != 1 || expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(f.Get("csrf"))) != 1 {
		return failure(http.StatusForbidden)
	}
	revision, err := strconv.Atoi(f.Get("expected_revision"))
	if err != nil || revision < 1 || revision > 2147483647 || strconv.Itoa(revision) != f.Get("expected_revision") {
		return failure(http.StatusBadRequest)
	}
	if f.Get("desired") != "installed" && f.Get("desired") != "removed" {
		return failure(http.StatusBadRequest)
	}
	ids := f["device_id"]
	if len(ids) < 1 || len(ids) > 1000 {
		return failure(http.StatusBadRequest)
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, err := profileRevisionParameter(id); err != nil || seen[id] {
			return failure(http.StatusBadRequest)
		}
		seen[id] = true
	}
	return revision, ids, f.Get("desired"), nil
}
