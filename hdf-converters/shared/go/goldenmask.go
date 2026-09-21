package shared

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
)

// The OSCAL exporters mint a fresh UUID per element and stamp the conversion
// moment into the document, so their output is different on every run and can
// never be frozen as-is. Masking makes it comparable.
//
// UUIDs are replaced by first-occurrence ordinal ("uuid-1", "uuid-2", ...) rather
// than a single constant, because OSCAL UUIDs REFERENCE each other: a party uuid
// reappears under responsible-parties, a risk uuid under related-risks. Collapsing
// them all to one placeholder would let Go and TypeScript emit entirely different
// reference graphs and still compare equal. Ordinals keep the graph observable:
// the same uuid always maps to the same ordinal, a different wiring maps
// differently, and the comparison fails as it should.
//
// Ordinals are assigned over a key-sorted walk so both languages number the UUIDs
// identically regardless of the order their serializers happen to emit keys.
//
// Mirrored by maskVolatileJSON in shared/typescript/golden-mask.ts. The two must
// stay in lockstep.

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// MaskVolatileJSON parses OSCAL/JSON output and blanks the values that change on
// every run: keys listed in volatileKeys, and every UUID (by first-occurrence
// ordinal). Returns the masked document for comparison, not for consumption.
func MaskVolatileJSON(data []byte, volatileKeys []string) (interface{}, error) {
	var doc interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	volatile := make(map[string]bool, len(volatileKeys))
	for _, k := range volatileKeys {
		volatile[k] = true
	}
	seen := map[string]string{}
	return maskValue(doc, volatile, seen), nil
}

func maskValue(v interface{}, volatile map[string]bool, seen map[string]string) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys) // canonical walk order, so ordinals match TypeScript's
		for _, k := range keys {
			if volatile[k] {
				out[k] = "(normalized)"
				continue
			}
			out[k] = maskValue(val[k], volatile, seen)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, item := range val {
			out[i] = maskValue(item, volatile, seen)
		}
		return out
	case string:
		return maskUUID(val, seen)
	default:
		return v
	}
}

func maskUUID(s string, seen map[string]string) string {
	// A "#<uuid>" fragment reference points at the uuid it names, so it shares that ordinal.
	if len(s) > 1 && s[0] == '#' && uuidPattern.MatchString(s[1:]) {
		return "#" + maskUUID(s[1:], seen)
	}
	if !uuidPattern.MatchString(s) {
		return s
	}
	if placeholder, ok := seen[s]; ok {
		return placeholder
	}
	placeholder := "uuid-" + strconv.Itoa(len(seen)+1)
	seen[s] = placeholder
	return placeholder
}
