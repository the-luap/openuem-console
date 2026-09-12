package ade

import "encoding/asn1"

// machineDER normalizes definite/indefinite BER lengths without interpreting
// signed content or reordering attributes. A caller must first apply boundedBER
// and the total byte limit. Apple's CMS uses indefinite constructed containers.
func machineDER(data []byte) ([]byte, error) {
	var convert func([]byte, bool, int) ([]byte, int, error)
	convert = func(input []byte, indefinite bool, depth int) ([]byte, int, error) {
		var output []byte
		pos := 0
		if depth > 16 {
			return nil, 0, ErrMachineInfo
		}
		for pos < len(input) {
			if len(input)-pos >= 2 && input[pos] == 0 && input[pos+1] == 0 {
				if !indefinite {
					return nil, 0, ErrMachineInfo
				}
				return output, pos + 2, nil
			}
			if len(input)-pos < 2 {
				return nil, 0, ErrMachineInfo
			}
			tag := input[pos]
			pos++
			// The CMS, certificate and plist envelope need only low tag numbers.
			if tag&31 == 31 {
				return nil, 0, ErrMachineInfo
			}
			size := int(input[pos])
			pos++
			isIndefinite := size == 128
			if size > 128 {
				n := size & 127
				if n > 4 || n > len(input)-pos {
					return nil, 0, ErrMachineInfo
				}
				size = 0
				for range n {
					if size > len(input)/256 {
						return nil, 0, ErrMachineInfo
					}
					size = size*256 + int(input[pos])
					pos++
				}
			}
			var value []byte
			if isIndefinite {
				if tag&32 == 0 {
					return nil, 0, ErrMachineInfo
				}
				part, used, err := convert(input[pos:], true, depth+1)
				if err != nil {
					return nil, 0, err
				}
				value, pos = part, pos+used
			} else {
				if size > len(input)-pos {
					return nil, 0, ErrMachineInfo
				}
				value = input[pos : pos+size]
				if tag&32 != 0 {
					part, used, err := convert(value, false, depth+1)
					if err != nil || used != size {
						return nil, 0, ErrMachineInfo
					}
					value = part
				}
				pos += size
			}
			encoded, err := asn1.Marshal(asn1.RawValue{Class: int(tag >> 6), Tag: int(tag & 31), IsCompound: tag&32 != 0, Bytes: value})
			if err != nil {
				return nil, 0, ErrMachineInfo
			}
			output = append(output, encoded...)
		}
		if indefinite {
			return nil, 0, ErrMachineInfo
		}
		return output, pos, nil
	}
	out, used, err := convert(data, false, 0)
	if err != nil || used != len(data) {
		return nil, ErrMachineInfo
	}
	return out, nil
}
