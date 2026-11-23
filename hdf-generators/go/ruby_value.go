package generators

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// rubyLabel matches a key Ruby accepts as a bare hash label ("key: value").
var rubyLabel = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// formatTag formats a single tag key-value pair as Ruby DSL whose key and
// value InSpec reads back unchanged. Parity: formatTag (TypeScript), pinned by
// testdata/ruby-tag-cases.json.
func formatTag(key string, value any) string {
	v := rubyValue(value)
	if rubyLabel.MatchString(key) {
		return "tag " + key + ": " + v
	}
	if lit := EscapeQuotes(key); !strings.HasPrefix(lit, "%q(") {
		return "tag " + lit + ": " + v
	}
	return "tag " + EscapeQuotes(key) + " => " + v
}

// rubyValue writes a JSON-shaped value as a Ruby literal: nil, true/false, a
// number as JavaScript prints it, a string through EscapeQuotes, an array, or
// a hash with string keys in sorted order. Other Go types are normalized
// through JSON first.
func rubyValue(value any) string {
	switch v := value.(type) {
	case nil:
		return "nil"
	case bool:
		return strconv.FormatBool(v)
	case string:
		return EscapeQuotes(v)
	case float64:
		return jsNumber(v)
	case []any:
		items := make([]string, len(v))
		for i, item := range v {
			items[i] = rubyValue(item)
		}
		return "[" + strings.Join(items, ", ") + "]"
	case map[string]any:
		if len(v) == 0 {
			return "{}"
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pairs := make([]string, len(keys))
		for i, k := range keys {
			pairs[i] = EscapeQuotes(k) + " => " + rubyValue(v[k])
		}
		return "{ " + strings.Join(pairs, ", ") + " }"
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return EscapeQuotes(err.Error())
		}
		var normalized any
		if err := json.Unmarshal(raw, &normalized); err != nil {
			return EscapeQuotes(string(raw))
		}
		return rubyValue(normalized)
	}
}

// jsNumber formats f as JavaScript's Number#toString does: decimal from 1e-6
// up to 1e21, exponent form outside it, and -0 as 0. NaN and infinity, which
// JSON cannot carry, are Ruby's Float constants.
func jsNumber(f float64) string {
	switch {
	case math.IsNaN(f):
		return "Float::NAN"
	case math.IsInf(f, 1):
		return "Float::INFINITY"
	case math.IsInf(f, -1):
		return "-Float::INFINITY"
	}
	if f == 0 {
		return "0"
	}
	if abs := math.Abs(f); abs >= 1e-6 && abs < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, exp, _ := strings.Cut(s, "e")
	sign, digits := exp[:1], strings.TrimLeft(exp[1:], "0")
	return mantissa + "e" + sign + digits
}
