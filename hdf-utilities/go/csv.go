package hdfutil

import "strings"

// csvFormulaTriggers are the leading characters that make a spreadsheet evaluate
// a cell as a formula rather than display it. Kept in sync with the TypeScript
// peer through testdata/csv-sanitize-cases.json, which both languages' tests
// read — a character added here and not there fails the shared-table test.
const csvFormulaTriggers = "=+-@|%"

// SanitizeCSVValue neutralises CSV formula injection by prepending a single
// quote to any value a spreadsheet would otherwise evaluate. Excel and
// LibreOffice treat a cell beginning with one of csvFormulaTriggers as a
// formula, so an attacker-controlled field like "=cmd|' /C calc'!A0" executes on
// open; the leading quote forces it to be read as text.
//
// This is policy rather than serialization, which is why it lives here and not
// in each exporter: Go's stdlib encoding/csv writes the file, exactly as
// encoding/xml does for XML while this package supplies
// ContainsXMLEntityDeclarations. The TypeScript side has a csv module because
// JavaScript has no stdlib CSV writer to leave the serializing to — the same
// reason hash and json are TypeScript-only.
//
// Only the FIRST character decides, and it is compared as a byte: a multi-byte
// UTF-8 character never begins with an ASCII trigger, so no non-ASCII value is
// falsely quoted.
func SanitizeCSVValue(value string) string {
	if value == "" {
		return value
	}
	if strings.IndexByte(csvFormulaTriggers, value[0]) >= 0 {
		return "'" + value
	}
	return value
}
