// Package cpe provides a CPE 2.3 URI parser with accept-and-warn semantics.
//
// Common Platform Enumeration (CPE) 2.3 URIs identify affected products and
// are emitted by container scanners (grype, twistlock, snyk) in vulnerability
// findings. Real-world scanner output frequently deviates slightly from the
// canonical 13-field form; strict rejection would block ingestion. Instead,
// any input that carries the "cpe:2.3:" prefix is best-effort parsed and
// deviations are reported via Warnings.
//
// Canonical form:
//
//	cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
//
// Reference: NIST IR 7695 (https://csrc.nist.gov/publications/detail/nistir/7695/final)
package hdfutil

import (
	"fmt"
	"strings"
)

// ParsedCpe is a parsed CPE 2.3 URI.
//
// Warnings collects any deviations from the canonical form (truncation,
// extra fields, unknown Part). An empty Warnings slice means the input was a
// strict 13-field, valid-part CPE.
type ParsedCpe struct {
	// Raw is the original input string, unmodified.
	Raw string
	// Part is the application kind: "a" (app), "o" (OS), "h" (hardware), or "*" (any).
	// Unknown values are preserved as-is and surfaced via a warning.
	Part      string
	Vendor    string
	Product   string
	Version   string
	Update    string
	Edition   string
	Language  string
	SwEdition string
	TargetSw  string
	TargetHw  string
	Other     string
	// Warnings holds deviation messages; nil/empty when input is canonical.
	Warnings []string
}

const (
	cpePrefix           = "cpe:2.3:"
	expectedTotalFields = 13 // "cpe", "2.3", and 11 product fields
	productFieldCount   = 11 // part + 10 attribute fields
)

// validParts is the set of CPE 2.3 part values defined by NIST IR 7695.
var validParts = map[string]struct{}{
	"a": {},
	"o": {},
	"h": {},
	"*": {},
}

// splitOnUnescapedColons splits a CPE body on unescaped ':' separators,
// honoring CPE 2.3's "\:" and "\\" escapes (NIST IR 7695 section 6.1.2.4).
// The returned slices have escapes resolved (a "\:" inside a field becomes ":",
// a "\\" becomes "\"). Unknown escapes preserve the backslash verbatim.
func splitOnUnescapedColons(body string) []string {
	var (
		result  []string
		current strings.Builder
	)
	for i := 0; i < len(body); i++ {
		ch := body[i]
		if ch == '\\' && i+1 < len(body) {
			next := body[i+1]
			if next == ':' || next == '\\' {
				current.WriteByte(next)
				i++
				continue
			}
			// Unknown escape — preserve the backslash and continue.
			current.WriteByte(ch)
			continue
		}
		if ch == ':' {
			result = append(result, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(ch)
	}
	result = append(result, current.String())
	return result
}

// ParseCpe parses a CPE 2.3 URI with accept-and-warn semantics.
//
// Behavior:
//   - Input missing the "cpe:2.3:" prefix → returns nil.
//   - Input with the prefix but fewer than 11 product fields → fields are
//     padded with "*" and a "truncated: ..." warning is added. A bare prefix
//     (cpe:2.3:) is treated as all-empty fields (no inferred wildcards).
//   - Input with more than 11 product fields → extras are dropped and an
//     "extra fields ignored" warning is added.
//   - Unknown Part value → preserved as-is in the result, "unknown part: X"
//     warning is added.
//   - "\:" and "\\" escapes are honored during splitting and unescaped in
//     the returned field values.
func ParseCpe(cpeURI string) *ParsedCpe {
	if !strings.HasPrefix(cpeURI, cpePrefix) {
		return nil
	}

	var warnings []string
	body := cpeURI[len(cpePrefix):]

	// Bare prefix (cpe:2.3:) is treated as "no useful data" — all fields stay
	// empty rather than being padded with wildcards.
	isBarePrefix := body == ""

	var bodyParts []string
	if !isBarePrefix {
		bodyParts = splitOnUnescapedColons(body)
	}

	totalFields := 2 + len(bodyParts) // prefix "cpe" and "2.3" + body parts
	if isBarePrefix {
		totalFields = 2
	}

	switch {
	case len(bodyParts) > productFieldCount:
		warnings = append(warnings, "extra fields ignored")
	case len(bodyParts) < productFieldCount:
		warnings = append(warnings,
			fmt.Sprintf("truncated: expected %d colon-separated fields, got %d",
				expectedTotalFields, totalFields))
	}

	padValue := "*"
	if isBarePrefix {
		padValue = ""
	}

	fields := make([]string, productFieldCount)
	for i := range fields {
		fields[i] = padValue
	}
	copy(fields, bodyParts) // copy stops at min(len(bodyParts), productFieldCount)

	part := fields[0]
	if _, ok := validParts[part]; !ok {
		warnings = append(warnings, "unknown part: "+part)
	}

	return &ParsedCpe{
		Raw:       cpeURI,
		Part:      part,
		Vendor:    fields[1],
		Product:   fields[2],
		Version:   fields[3],
		Update:    fields[4],
		Edition:   fields[5],
		Language:  fields[6],
		SwEdition: fields[7],
		TargetSw:  fields[8],
		TargetHw:  fields[9],
		Other:     fields[10],
		Warnings:  warnings,
	}
}
