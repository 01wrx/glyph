package discover

import (
	"errors"
	"sort"
	"strconv"
)

func marshal(v any) ([]byte, error) {
	return appendValue(nil, v)
}

func appendValue(dst []byte, v any) ([]byte, error) {
	switch x := v.(type) {
	case string:
		return appendString(dst, x), nil
	case []byte:
		return appendString(dst, string(x)), nil
	case int:
		return appendInt(dst, int64(x)), nil
	case int64:
		return appendInt(dst, x), nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		dst = append(dst, 'd')
		for _, k := range keys {
			dst = appendString(dst, k)
			var err error
			dst, err = appendValue(dst, x[k])
			if err != nil {
				return nil, err
			}
		}
		return append(dst, 'e'), nil
	case []any:
		dst = append(dst, 'l')
		for _, item := range x {
			var err error
			dst, err = appendValue(dst, item)
			if err != nil {
				return nil, err
			}
		}
		return append(dst, 'e'), nil
	default:
		return nil, errors.New("discover: bad bencode")
	}
}

func appendString(dst []byte, s string) []byte {
	dst = strconv.AppendInt(dst, int64(len(s)), 10)
	dst = append(dst, ':')
	return append(dst, s...)
}

func appendInt(dst []byte, n int64) []byte {
	dst = append(dst, 'i')
	dst = strconv.AppendInt(dst, n, 10)
	return append(dst, 'e')
}

func unmarshal(b []byte) (any, error) {
	if len(b) == 0 || len(b) > 64*1024 {
		return nil, errors.New("discover: bad bencode")
	}
	v, rest, err := parseValue(b, 0)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("discover: bad bencode")
	}
	return v, nil
}

func parseValue(b []byte, depth int) (any, []byte, error) {
	if len(b) == 0 || depth > 8 {
		return nil, nil, errors.New("discover: bad bencode")
	}
	switch b[0] {
	case 'i':
		return parseInt(b)
	case 'l':
		return parseList(b, depth)
	case 'd':
		return parseDict(b, depth)
	default:
		if b[0] < '0' || b[0] > '9' {
			return nil, nil, errors.New("discover: bad bencode")
		}
		return parseString(b)
	}
}

func parseString(b []byte) (string, []byte, error) {
	i := 0
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	if i == 0 || i >= len(b) || b[i] != ':' || (i > 1 && b[0] == '0') {
		return "", nil, errors.New("discover: bad bencode")
	}
	n, err := strconv.Atoi(string(b[:i]))
	if err != nil || n < 0 || i+1+n > len(b) {
		return "", nil, errors.New("discover: bad bencode")
	}
	return string(b[i+1 : i+1+n]), b[i+1+n:], nil
}

func parseInt(b []byte) (int64, []byte, error) {
	if len(b) < 3 || b[0] != 'i' {
		return 0, nil, errors.New("discover: bad bencode")
	}
	end := 1
	for end < len(b) && b[end] != 'e' {
		end++
	}
	if end >= len(b) || end == 1 {
		return 0, nil, errors.New("discover: bad bencode")
	}
	raw := string(b[1:end])
	if raw == "-0" || (len(raw) > 1 && raw[0] == '0') || (len(raw) > 2 && raw[0] == '-' && raw[1] == '0') {
		return 0, nil, errors.New("discover: bad bencode")
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, nil, errors.New("discover: bad bencode")
	}
	return n, b[end+1:], nil
}

func parseList(b []byte, depth int) ([]any, []byte, error) {
	rest := b[1:]
	var out []any
	for len(rest) > 0 && rest[0] != 'e' {
		var item any
		var err error
		item, rest, err = parseValue(rest, depth+1)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, item)
	}
	if len(rest) == 0 || rest[0] != 'e' {
		return nil, nil, errors.New("discover: bad bencode")
	}
	return out, rest[1:], nil
}

func parseDict(b []byte, depth int) (map[string]any, []byte, error) {
	rest := b[1:]
	out := map[string]any{}
	prev := ""
	for len(rest) > 0 && rest[0] != 'e' {
		var key string
		var err error
		key, rest, err = parseString(rest)
		if err != nil || key <= prev {
			return nil, nil, errors.New("discover: bad bencode")
		}
		prev = key
		var val any
		val, rest, err = parseValue(rest, depth+1)
		if err != nil {
			return nil, nil, err
		}
		out[key] = val
	}
	if len(rest) == 0 || rest[0] != 'e' {
		return nil, nil, errors.New("discover: bad bencode")
	}
	return out, rest[1:], nil
}

func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}
