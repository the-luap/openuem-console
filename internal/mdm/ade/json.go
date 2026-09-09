package ade

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode"
)

var errJSON = errors.New("invalid ADE response")

// encoding/json matches struct fields with Unicode simple case folding. Detect
// aliases before unmarshalling so differently cased keys cannot replace a
// previously validated credential or response field.
func foldedJSONName(s string) string {
	name := []rune(s)
	for i, r := range name {
		minimum := r
		for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
			minimum = min(minimum, folded)
		}
		name[i] = minimum
	}
	return string(name)
}

// Apple can add response fields. Permit additive fields while rejecting duplicate
// names, trailing objects and excessive structure before binding known fields.
func decodeJSON(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	nodes := 0
	var value func(int) error
	value = func(depth int) error {
		nodes++
		if depth > 16 || nodes > 40000 {
			return errJSON
		}
		t, err := d.Token()
		if err != nil {
			return errJSON
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				name, ok := k.(string)
				name = foldedJSONName(name)
				if err != nil || !ok || keys[name] {
					return errJSON
				}
				keys[name] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errJSON
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errJSON
			}
		default:
			return errJSON
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errJSON
	}
	if json.Unmarshal(data, out) != nil {
		return errJSON
	}
	return nil
}
