// Package hdftoxml serializes an HDF Results JSON document to XML.
//
// The serializer is generic, lossless, and order-preserving: it walks the
// parsed HDF JSON tree and emits one element per key in source-JSON order,
// with no hand-maintained struct mirror. Every field the input carries appears
// in the output, so the XML never silently lags a schema addition (the previous
// struct-mirror approach dropped ~30 post-v3.2 fields). The TypeScript converter
// walks the same normalized JSON in the same order and produces output that is
// identical after the shared XML golden normalization.
package hdftoxml

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// pluralToSingular maps a container (plural) key to the element name emitted for
// each of its array items. The first six entries reproduce the historical
// struct-tag child names byte-for-byte (note components -> target, kept for
// backward compatibility); the rest give the post-v3.2 containers a sensible
// singular. Any array key not listed here falls back to <item>, which keeps the
// serializer lossless and fully generic for fields added later.
//
// Mirrored by pluralToSingular in the TypeScript converter — keep the two in
// lockstep so both languages emit identical element names.
var pluralToSingular = map[string]string{
	"baselines":        "baseline",
	"requirements":     "requirement",
	"results":          "result",
	"refs":             "ref",
	"descriptions":     "description",
	"components":       "target",
	"statusOverrides":  "statusOverride",
	"poams":            "poam",
	"milestones":       "milestone",
	"cvss":             "cvss",
	"cwe":              "cwe",
	"groups":           "group",
	"affectedPackages": "affectedPackage",
}

// singularFor returns the per-item element name for an array under key, falling
// back to the generic "item" for any unmapped key.
func singularFor(key string) string {
	if s, ok := pluralToSingular[key]; ok {
		return s
	}
	return "item"
}

// ConvertHDFToXML converts an HDF Results JSON document to XML.
func ConvertHDFToXML(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("hdf-to-xml: empty input")
	}
	if err := shared.ValidateJSONSize(input, "hdf-to-xml", 0); err != nil {
		return nil, fmt.Errorf("hdf-to-xml: %w", err)
	}

	// Rewrite zone-less timestamps to canonical trimmed-UTC RFC3339 before the
	// generic walk, exactly as DecodeHDF does for the typed path. This is what
	// keeps the walker lossless *and* correct: InSpec's "2026-03-25T22:56:27.736808"
	// becomes "2026-03-25T22:56:27.736Z" in the byte stream, so emitting the
	// string verbatim yields the canonical form both languages agree on.
	normalized := hdfutil.NormalizeHDFTimestamps(input)

	root, err := decodeOrdered(normalized)
	if err != nil {
		return nil, fmt.Errorf("invalid HDF JSON: %w", err)
	}

	obj, ok := root.(*orderedMap)
	if !ok {
		return nil, fmt.Errorf("invalid HDF structure: missing baselines field")
	}
	baselines, found := obj.get("baselines")
	if !found {
		return nil, fmt.Errorf("invalid HDF structure: missing baselines field")
	}
	if _, isArr := baselines.([]interface{}); !isArr {
		return nil, fmt.Errorf("invalid HDF structure: baselines must be an array")
	}

	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := writeValue(enc, "HdfResults", obj); err != nil {
		return nil, fmt.Errorf("failed to marshal XML: %w", err)
	}
	if err := enc.Flush(); err != nil {
		return nil, fmt.Errorf("failed to marshal XML: %w", err)
	}

	return append([]byte(xml.Header), buf.Bytes()...), nil
}

// orderedMap is a JSON object that remembers its keys in source order, which
// map[string]interface{} discards. Preserving order is what lets the Go and
// TypeScript serializers emit byte-identical element sequences.
type orderedMap struct {
	members []member
}

type member struct {
	key string
	val interface{}
}

func (o *orderedMap) get(key string) (interface{}, bool) {
	for _, m := range o.members {
		if m.key == key {
			return m.val, true
		}
	}
	return nil, false
}

// decodeOrdered parses JSON into an order-preserving tree: objects become
// *orderedMap, arrays become []interface{}, and scalars become string,
// json.Number (UseNumber, so the original numeric text is available), bool, or
// nil.
func decodeOrdered(data []byte) (interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return decodeValue(dec)
}

func decodeValue(dec *json.Decoder) (interface{}, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil // string, json.Number, bool, or nil
	}
	switch delim {
	case '{':
		obj := &orderedMap{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyTok.(string)
			if !ok {
				return nil, fmt.Errorf("expected string object key, got %v", keyTok)
			}
			val, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			obj.members = append(obj.members, member{key: key, val: val})
		}
		if _, err := dec.Token(); err != nil { // consume '}'
			return nil, err
		}
		return obj, nil
	case '[':
		arr := []interface{}{}
		for dec.More() {
			val, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
		if _, err := dec.Token(); err != nil { // consume ']'
			return nil, err
		}
		return arr, nil
	default:
		return nil, fmt.Errorf("unexpected delimiter %q", delim)
	}
}

// writeValue emits one XML element named name for val:
//   - object: <name> wrapping one child element per key, in source order; keys
//     whose value is null are omitted (matching the old omitempty semantics).
//   - scalar array: the key is repeated, unwrapped — <name>a</name><name>b</name>
//     — the idiomatic form for repeated simple values (e.g. tags nist/cci).
//   - object array: <name> wrapping one <singular(name)> element per item.
//   - empty array: an empty wrapper element <name></name>.
//   - scalar: <name>text</name>.
func writeValue(enc *xml.Encoder, name string, val interface{}) error {
	start := xml.StartElement{Name: xml.Name{Local: name}}
	switch v := val.(type) {
	case *orderedMap:
		if err := enc.EncodeToken(start); err != nil {
			return err
		}
		for _, m := range v.members {
			if m.val == nil {
				continue
			}
			if err := writeValue(enc, m.key, m.val); err != nil {
				return err
			}
		}
		return enc.EncodeToken(start.End())
	case []interface{}:
		if len(v) == 0 {
			// Empty array -> empty wrapper element (keeps <baselines></baselines>
			// / <requirements></requirements> for zero-length containers).
			if err := enc.EncodeToken(start); err != nil {
				return err
			}
			return enc.EncodeToken(start.End())
		}
		if allScalar(v) {
			// Scalar array -> repeated, unwrapped element.
			for _, item := range v {
				if item == nil {
					continue
				}
				if err := writeValue(enc, name, item); err != nil {
					return err
				}
			}
			return nil
		}
		// Object array -> wrapper element with one singular-named child per item.
		child := singularFor(name)
		if err := enc.EncodeToken(start); err != nil {
			return err
		}
		for _, item := range v {
			if item == nil {
				continue
			}
			if err := writeValue(enc, child, item); err != nil {
				return err
			}
		}
		return enc.EncodeToken(start.End())
	default:
		if err := enc.EncodeToken(start); err != nil {
			return err
		}
		if err := enc.EncodeToken(xml.CharData(scalarText(v))); err != nil {
			return err
		}
		return enc.EncodeToken(start.End())
	}
}

// allScalar reports whether every item in an array is a JSON scalar (string,
// number, bool, or null). Nested objects and arrays make it false, selecting the
// wrapped object-array rendering. A null item counts as scalar (it is skipped on
// emit), so ["a", null] still renders unwrapped.
func allScalar(items []interface{}) bool {
	for _, item := range items {
		switch item.(type) {
		case *orderedMap, []interface{}:
			return false
		}
	}
	return true
}

// scalarText renders a JSON scalar as text. Numbers go through ParseFloat +
// FormatFloat('f') so the rendering is byte-identical to JavaScript's default
// Number-to-string for every value HDF carries (impacts, scores, line numbers,
// durations) — no exponent, no forced ".0".
func scalarText(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	case json.Number:
		if f, err := strconv.ParseFloat(string(s), 64); err == nil {
			return strconv.FormatFloat(f, 'f', -1, 64)
		}
		return string(s)
	case bool:
		if s {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprint(v)
	}
}
