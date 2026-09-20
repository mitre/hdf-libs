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
// The FIRST NON-WHITESPACE character decides: spreadsheets trim leading
// whitespace before deciding a cell is a formula, so " =1+1" still executes and
// a byte-zero-only check would miss it (OWASP CSV Injection guidance). Only
// ASCII whitespace is skipped and the trigger is compared as a byte, so a
// multi-byte UTF-8 rune (which never begins with an ASCII trigger or whitespace)
// stops the scan and is never falsely quoted. The quote prefixes the whole
// value, leaving the leading whitespace intact — the export stays lossless.
func SanitizeCSVValue(value string) string {
	i := 0
	for i < len(value) && isCSVLeadingWhitespace(value[i]) {
		i++
	}
	if i < len(value) && strings.IndexByte(csvFormulaTriggers, value[i]) >= 0 {
		return "'" + value
	}
	return value
}

// isCSVLeadingWhitespace reports whether b is ASCII whitespace a spreadsheet
// trims before formula evaluation (space, tab, CR, LF).
func isCSVLeadingWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}
