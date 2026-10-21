package config

import (
	"fmt"
	"strconv"
	"strings"
)

// parseTOML reads the small TOML subset reclaim's config uses: [tables],
// key = "string" | number | bool | ["array", "of", "strings"] (arrays may
// span lines), and # comments. Keys are returned as "table.key".
func parseTOML(src string) (map[string]any, error) {
	out := map[string]any{}
	table := ""
	lines := strings.Split(src, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(stripComment(lines[i]))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") || strings.HasPrefix(line, "[[") {
				return nil, fmt.Errorf("line %d: unsupported table header %q", i+1, line)
			}
			table = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", i+1)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		start := i
		if strings.HasPrefix(val, "[") {
			for !arrayClosed(val) && i+1 < len(lines) {
				i++
				val += " " + strings.TrimSpace(stripComment(lines[i]))
			}
		}
		v, err := parseValue(val)
		if err != nil {
			return nil, fmt.Errorf("line %d: %s: %w", start+1, key, err)
		}
		if table != "" {
			key = table + "." + key
		}
		out[key] = v
	}
	return out, nil
}

// stripComment removes a # comment that is not inside a string.
func stripComment(s string) string {
	inStr := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if inStr {
				i++
			}
		case '"':
			inStr = !inStr
		case '#':
			if !inStr {
				return s[:i]
			}
		}
	}
	return s
}

func arrayClosed(s string) bool {
	inStr := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if inStr {
				i++
			}
		case '"':
			inStr = !inStr
		case ']':
			if !inStr {
				return true
			}
		}
	}
	return false
}

func parseValue(s string) (any, error) {
	switch {
	case s == "true":
		return true, nil
	case s == "false":
		return false, nil
	case strings.HasPrefix(s, `"`):
		v, err := strconv.Unquote(s)
		if err != nil {
			return nil, fmt.Errorf("bad string %s", s)
		}
		return v, nil
	case strings.HasPrefix(s, "'"):
		if len(s) < 2 || !strings.HasSuffix(s, "'") {
			return nil, fmt.Errorf("bad literal string %s", s)
		}
		return s[1 : len(s)-1], nil
	case strings.HasPrefix(s, "["):
		inner := strings.TrimSpace(s[1:strings.LastIndex(s, "]")])
		var items []string
		for inner != "" {
			inner = strings.TrimLeft(inner, " \t,")
			if inner == "" {
				break
			}
			var item string
			switch inner[0] {
			case '"':
				end := closingQuote(inner)
				if end < 0 {
					return nil, fmt.Errorf("unterminated string in array")
				}
				v, err := strconv.Unquote(inner[:end+1])
				if err != nil {
					return nil, err
				}
				item, inner = v, inner[end+1:]
			case '\'':
				end := strings.IndexByte(inner[1:], '\'')
				if end < 0 {
					return nil, fmt.Errorf("unterminated string in array")
				}
				item, inner = inner[1:end+1], inner[end+2:]
			default:
				return nil, fmt.Errorf("arrays may only hold strings")
			}
			items = append(items, item)
			inner = strings.TrimSpace(inner)
		}
		return items, nil
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return n, nil
	}
	return nil, fmt.Errorf("unsupported value %q", s)
}

func closingQuote(s string) int {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return -1
}
