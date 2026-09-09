package apple

import (
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// JSON is an editor input format only. Preserve booleans, integers, real
// numbers, dictionaries and arrays as plist types. Null has no plist equivalent.
func ParsePlatformSSOProviderData(raw string) (map[string]any, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	if len(raw) > 16384 || !utf8.ValidString(raw) {
		return nil, errors.New("SSO provider data must be valid UTF-8 and contain at most 16 KiB")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	value, err := readSSOProviderValue(decoder, 0, &nodes)
	if err != nil {
		return nil, errors.New("SSO provider data must be a bounded JSON dictionary with unique keys and no null values")
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, errors.New("SSO provider data must contain exactly one JSON dictionary")
	}
	dictionary, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("SSO provider data must be a JSON dictionary")
	}
	return dictionary, nil
}

func readSSOProviderValue(decoder *json.Decoder, depth int, nodes *int) (any, error) {
	*nodes++
	if depth > 16 || *nodes > 1024 {
		return nil, ErrConflict
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			result := map[string]any{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				name, ok := key.(string)
				if !ok || !validMacAppText(name, 255) {
					return nil, ErrConflict
				}
				if _, exists := result[name]; exists {
					return nil, ErrConflict
				}
				item, err := readSSOProviderValue(decoder, depth+1, nodes)
				if err != nil {
					return nil, err
				}
				result[name] = item
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrConflict
			}
			return result, nil
		case '[':
			result := []any{}
			for decoder.More() {
				item, err := readSSOProviderValue(decoder, depth+1, nodes)
				if err != nil {
					return nil, err
				}
				result = append(result, item)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrConflict
			}
			return result, nil
		default:
			return nil, ErrConflict
		}
	case json.Number:
		if strings.ContainsAny(string(value), ".eE") {
			return strconv.ParseFloat(string(value), 64)
		}
		if strings.HasPrefix(string(value), "-") {
			return strconv.ParseInt(string(value), 10, 64)
		}
		return strconv.ParseUint(string(value), 10, 64)
	case string:
		for _, r := range value {
			if r < 32 && r != '\t' && r != '\n' && r != '\r' || r == 0xfffe || r == 0xffff {
				return nil, ErrConflict
			}
		}
		return value, nil
	case bool:
		return value, nil
	default:
		return nil, ErrConflict
	}
}
