package audit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type Filter struct {
	Scope    access.Scope `json:"scope"`
	Source   string       `json:"source"`
	Actor    string       `json:"actor"`
	Action   string       `json:"action"`
	Resource string       `json:"resource"`
	Result   string       `json:"result"`
	From     time.Time    `json:"from"`
	Until    time.Time    `json:"until"`
}

func textFilter(value string) bool {
	return len(value) <= 255 && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func (f Filter) Validate() error {
	if f.Scope.TenantID < 0 || f.Scope.SiteID < 0 || (f.Scope.TenantID == 0 && f.Scope.SiteID != 0) || f.From.IsZero() || f.Until.IsZero() || !f.From.Before(f.Until) {
		return ErrInvalid
	}
	for _, value := range []string{f.Actor, f.Action, f.Resource} {
		if !textFilter(value) {
			return ErrInvalid
		}
	}
	if f.Source != "" && !validSource(f.Source) {
		return ErrInvalid
	}
	switch f.Result {
	case "", "recorded", "success", "failure", "denied", "deferred", "cancelled":
	default:
		return ErrInvalid
	}
	return nil
}

func validSource(source string) bool {
	for _, candidate := range sourceQueries {
		if source == candidate.name {
			return true
		}
	}
	return false
}

func (f Filter) digest() string {
	f.From, f.Until = f.From.UTC(), f.Until.UTC()
	data, _ := json.Marshal(f)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

type cursor struct {
	At     time.Time `json:"at"`
	Source string    `json:"source"`
	ID     int64     `json:"id"`
	Filter string    `json:"filter"`
}

func encodeCursor(f Filter, event Event) string {
	data, _ := json.Marshal(cursor{At: event.CreatedAt.UTC(), Source: event.Source, ID: event.ID, Filter: f.digest()})
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeCursor(f Filter, encoded string) (cursor, error) {
	if encoded == "" {
		return cursor{At: f.Until, Source: "zz", ID: 1<<63 - 1}, nil
	}
	if len(encoded) > 1024 {
		return cursor{}, ErrInvalid
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return cursor{}, ErrInvalid
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var c cursor
	if err = decoder.Decode(&c); err != nil {
		return cursor{}, ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || c.ID <= 0 || !validSource(c.Source) || c.Filter != f.digest() || c.At.Before(f.From) || !c.At.Before(f.Until) {
		return cursor{}, ErrInvalid
	}
	return c, nil
}
