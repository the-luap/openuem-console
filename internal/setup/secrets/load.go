// Package secrets provisions installation credentials and reads protected
// runtime inputs without putting their contents in arguments or error messages.
package secrets

import (
	"bytes"
	"errors"
	"io"

	"github.com/open-uem/nats/enrollment/keyfile"
)

var ErrConfiguration = errors.New("installation secrets require valid, unambiguous protected configuration")
var ErrState = errors.New("installation secret state is incomplete, changed or not private; existing material was retained")

type Inputs struct {
	JWT, Master         string
	JWTFile, MasterFile string
	Required            bool
}

type Runtime struct {
	JWT, Master string
}

// Load permits exactly one source for each credential. File errors never fall
// back to another source. Legacy raw inputs remain compatible; individual mode
// requires both keys. Files always use bounded printable ASCII, with an optional
// single LF or CRLF terminator. The master key is the actual 32-byte AES input,
// not a hex/base64 encoding which consumers would need to decode.
func Load(input Inputs) (Runtime, error) {
	var result Runtime
	var err error
	result.JWT, err = resolve(input.JWT, input.JWTFile, 32, 128)
	if err != nil {
		return Runtime{}, err
	}
	result.Master, err = resolve(input.Master, input.MasterFile, 32, 32)
	if err != nil {
		return Runtime{}, err
	}
	if result.JWT == "" || input.Required && (len(result.JWT) < 32 || len(result.JWT) > 1024 || len(result.Master) != 32) {
		return Runtime{}, ErrConfiguration
	}
	return result, nil
}

func resolve(raw, path string, minimum, maximum int) (string, error) {
	if path == "" {
		return raw, nil
	}
	if raw != "" {
		return "", ErrConfiguration
	}
	data, err := read(path, int64(maximum+2))
	if err != nil {
		return "", ErrConfiguration
	}
	defer clear(data)
	value := bytes.TrimSuffix(data, []byte("\n"))
	if len(value) != len(data) {
		value = bytes.TrimSuffix(value, []byte("\r"))
	}
	if len(value) < minimum || len(value) > maximum || bytes.ContainsFunc(value, func(r rune) bool { return r < 33 || r > 126 }) {
		return "", ErrConfiguration
	}
	return string(value), nil
}

func read(path string, limit int64) ([]byte, error) {
	file, err := keyfile.Open(path, limit)
	if err != nil {
		return nil, ErrState
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		clear(data)
		return nil, ErrState
	}
	return data, nil
}
