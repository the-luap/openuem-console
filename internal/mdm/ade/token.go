// Package ade implements Apple's Automated Device Enrollment service boundary.
package ade

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/mail"
	"strings"
	"time"

	"github.com/smallstep/pkcs7"
)

const MaxTokenFile = 1 << 20
const maxTokenJSON = 64 << 10

var ErrToken = errors.New("invalid or expired Automated Device Enrollment token")

type tokenData struct {
	ConsumerKey    string    `json:"consumer_key"`
	ConsumerSecret string    `json:"consumer_secret"`
	AccessToken    string    `json:"access_token"`
	AccessSecret   string    `json:"access_secret"`
	Expiry         time.Time `json:"access_token_expiry"`
}

// Token owns credentials. Its diagnostic and JSON representations never expose
// secrets. Close releases references and clears owned encoding buffers; Go may
// retain internal string or cryptographic copies until garbage collection.
type Token struct {
	data    tokenData
	encoded []byte
}

func (*Token) String() string               { return "[private Automated Device Enrollment token]" }
func (t *Token) GoString() string           { return t.String() }
func (*Token) MarshalJSON() ([]byte, error) { return nil, ErrToken }
func (t *Token) ExpiresAt() time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.data.Expiry
}
func (t *Token) Close() {
	if t != nil {
		clear(t.encoded)
		t.encoded = nil
		t.data = tokenData{}
	}
}

// Bytes returns an owned copy for immediate encryption at rest. Clear it after use.
func (t *Token) Bytes() []byte {
	if t == nil {
		return nil
	}
	return bytes.Clone(t.encoded)
}

func ParseToken(data []byte, now time.Time) (*Token, error) {
	if len(data) == 0 || len(data) > maxTokenJSON {
		return nil, ErrToken
	}
	var v tokenData
	if decodeJSON(data, &v) != nil {
		return nil, ErrToken
	}
	for _, s := range []string{v.ConsumerKey, v.ConsumerSecret, v.AccessToken, v.AccessSecret} {
		if !opaque(s, 4096) {
			return nil, ErrToken
		}
	}
	if !v.Expiry.After(now.Add(time.Minute)) {
		return nil, ErrToken
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, ErrToken
	}
	return &Token{data: v, encoded: encoded}, nil
}

func opaque(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, b := range []byte(s) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

// DecryptToken accepts the S/MIME file from Apple, or its raw CMS envelope.
// Plain credentials are accepted only by ParseToken for protected stored data.
// Successful decryption is not account authentication: callers must verify /account.
func DecryptToken(data []byte, cert *x509.Certificate, key *rsa.PrivateKey, now time.Time) (token *Token, err error) {
	if len(data) == 0 || len(data) > MaxTokenFile || cert == nil || key == nil || key.N == nil || key.N.BitLen() < 2048 || !key.PublicKey.Equal(cert.PublicKey) || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, ErrToken
	}
	// Keep errors from the third-party CMS decoder private, including malformed
	// algorithm parameters. Structural limits below bound BER recursion first.
	defer func() {
		if recover() != nil {
			token, err = nil, ErrToken
		}
	}()
	der := data
	if data[0] != 0x30 {
		der, err = mimeBody(data, true)
		if err != nil {
			return nil, ErrToken
		}
		defer clear(der)
	}
	if !boundedBER(der) {
		return nil, ErrToken
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, ErrToken
	}
	plain, err := p7.Decrypt(cert, key)
	if err != nil {
		return nil, ErrToken
	}
	defer clear(plain)
	if len(plain) > maxTokenJSON {
		return nil, ErrToken
	}
	if !bytes.HasPrefix(bytes.TrimSpace(plain), []byte("{")) {
		plain, err = mimeBody(plain, false)
		if err != nil {
			return nil, ErrToken
		}
		defer clear(plain)
	}
	return ParseToken(plain, now)
}

func mimeBody(data []byte, encrypted bool) ([]byte, error) {
	m, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, ErrToken
	}
	for _, k := range []string{"Content-Type", "Content-Transfer-Encoding"} {
		if len(m.Header[k]) != 1 {
			return nil, ErrToken
		}
	}
	kind, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil {
		return nil, ErrToken
	}
	if encrypted {
		if kind != "application/pkcs7-mime" && kind != "application/x-pkcs7-mime" {
			return nil, ErrToken
		}
		if v := params["smime-type"]; v != "" && v != "enveloped-data" {
			return nil, ErrToken
		}
	} else if kind != "text/plain" && kind != "application/json" {
		return nil, ErrToken
	}
	var r io.Reader = m.Body
	switch strings.ToLower(m.Header.Get("Content-Transfer-Encoding")) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, r)
	case "7bit", "8bit", "binary":
		if encrypted {
			return nil, ErrToken
		}
	default:
		return nil, ErrToken
	}
	out, err := io.ReadAll(io.LimitReader(r, MaxTokenFile+1))
	if err != nil || len(out) > MaxTokenFile {
		clear(out)
		return nil, ErrToken
	}
	return out, nil
}

// Apple S/MIME may use indefinite-length BER. Bound its nesting and node count
// before the CMS library converts BER to DER; encrypted primitive bytes are opaque.
func boundedBER(data []byte) bool {
	nodes := 0
	var walk func([]byte, int, bool) (int, bool)
	walk = func(b []byte, depth int, indefinite bool) (int, bool) {
		if depth > 16 {
			return 0, false
		}
		pos := 0
		for pos < len(b) {
			if len(b)-pos >= 2 && b[pos] == 0 && b[pos+1] == 0 {
				return pos + 2, indefinite
			}
			nodes++
			if nodes > 4096 || len(b)-pos < 2 {
				return 0, false
			}
			tag := b[pos]
			pos++
			if tag&31 == 31 {
				n := 0
				for {
					if pos >= len(b) || n == 4 {
						return 0, false
					}
					v := b[pos]
					pos++
					n++
					if v&128 == 0 {
						break
					}
				}
			}
			if pos >= len(b) {
				return 0, false
			}
			size := int(b[pos])
			pos++
			if size == 128 {
				if tag&32 == 0 {
					return 0, false
				}
				n, ok := walk(b[pos:], depth+1, true)
				if !ok {
					return 0, false
				}
				pos += n
				if depth == 0 && pos != len(b) {
					return 0, false
				}
				continue
			}
			if size > 128 {
				n := size & 127
				if n > 4 || n > len(b)-pos {
					return 0, false
				}
				size = 0
				for range n {
					if size > len(b)/256 {
						return 0, false
					}
					size = size*256 + int(b[pos])
					pos++
				}
			}
			if size > len(b)-pos {
				return 0, false
			}
			if tag&32 != 0 {
				n, ok := walk(b[pos:pos+size], depth+1, false)
				if !ok || n != size {
					return 0, false
				}
			}
			pos += size
			if depth == 0 && pos != len(b) {
				return 0, false
			}
		}
		return pos, !indefinite
	}
	if len(data) < 2 || data[0] != 0x30 {
		return false
	}
	n, ok := walk(data, 0, false)
	return ok && n == len(data)
}
