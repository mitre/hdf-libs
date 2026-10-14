// BOM format fingerprints + DetectFormat dispatcher.
//
// Self-contained structural detectors for the three supported BOM formats.
// Detection precedence: an ML-BOM is a CycloneDX document with a
// machine-learning-model component, so the ML detector must win over the plain
// CycloneDX detector.

package bom

import "strings"

// FormatDetection reports a detected BOM format and a 0..1 confidence.
type FormatDetection struct {
	Format     string
	Confidence float64
}

// isCycloneDXFormat reports whether a bomFormat value names CycloneDX, ASCII
// case-insensitively. The spec requires the exact spelling, but a document this
// package declines falls through to HDF document detection, which reaches
// `components` after five more specific keys — so a CycloneDX SBOM would be
// filed as an HDF system, a worse answer than "not a BOM". Case only: a value
// with surrounding whitespace is a different value.
func isCycloneDXFormat(v any) bool {
	s, ok := v.(string)
	return ok && asciiLower(s) == "cyclonedx"
}

// DetectCycloneDX reports confidence that input is a CycloneDX document
// (bomFormat naming CycloneDX, any casing). Returns 0 or 1.
func DetectCycloneDX(input any) float64 {
	obj := asRecord(input)
	if obj != nil && isCycloneDXFormat(obj["bomFormat"]) {
		return 1
	}
	return 0
}

// DetectCycloneDXML reports confidence that input is a CycloneDX ML-BOM: a
// CycloneDX document with at least one machine-learning-model component.
// Strictly more specific than plain CycloneDX. Returns 0 or 1.
func DetectCycloneDXML(input any) float64 {
	obj := asRecord(input)
	if obj == nil || !isCycloneDXFormat(obj["bomFormat"]) {
		return 0
	}
	components, ok := obj["components"].([]any)
	if !ok {
		return 0
	}
	for _, c := range components {
		if asRecord(c)["type"] == "machine-learning-model" {
			return 1
		}
	}
	return 0
}

// DetectSPDX reports confidence that input is an SPDX document (a non-empty
// spdxVersion string is present). Returns 0 or 1.
func DetectSPDX(input any) float64 {
	obj := asRecord(input)
	if obj != nil && asString(obj["spdxVersion"]) != "" {
		return 1
	}
	return 0
}

// DetectSPDX3 reports confidence that input is an SPDX 3.0 AI/Dataset document
// (JSON-LD): an `@context` plus an `@graph` array carrying at least one
// ai_AIPackage or dataset_DatasetPackage element. Structurally disjoint from the
// SPDX 2.3 detector (which keys on spdxVersion), so the two never conflict.
// Returns 0 or 1.
func DetectSPDX3(input any) float64 {
	obj := asRecord(input)
	if obj == nil {
		return 0
	}
	if _, ok := obj["@context"]; !ok {
		return 0
	}
	graph, ok := obj["@graph"].([]any)
	if !ok {
		return 0
	}
	for _, el := range graph {
		t := asString(asRecord(el)["type"])
		if t == "ai_AIPackage" || t == "dataset_DatasetPackage" {
			return 1
		}
	}
	return 0
}

// DetectSPDX3Security reports confidence that input is an SPDX 3.0 security /
// VEX document (JSON-LD): an `@context` plus an `@graph` array carrying at least
// one security_Vex*VulnAssessmentRelationship element (the four VEX assessment
// subtypes: Affected, NotAffected, Fixed, UnderInvestigation). Structurally
// disjoint from the SPDX 2.3 detector (which keys on spdxVersion) and from the
// SPDX 3.0 AI/Dataset detector (which keys on ai_AIPackage /
// dataset_DatasetPackage), so none of the three conflict. Returns 0 or 1.
func DetectSPDX3Security(input any) float64 {
	obj := asRecord(input)
	if obj == nil {
		return 0
	}
	if _, ok := obj["@context"]; !ok {
		return 0
	}
	graph, ok := obj["@graph"].([]any)
	if !ok {
		return 0
	}
	for _, el := range graph {
		if isVexAssessmentType(asString(asRecord(el)["type"])) {
			return 1
		}
	}
	return 0
}

// isVexAssessmentType reports whether an SPDX-3 element type is one of the four
// VEX assessment relationship subtypes.
func isVexAssessmentType(t string) bool {
	return strings.HasPrefix(t, "security_Vex") && strings.HasSuffix(t, "VulnAssessmentRelationship")
}

// isSPDX3Context reports whether a JSON-LD @context names an SPDX 3 vocabulary.
//
// The value may be a string, an array, or an object whose values are either;
// an SPDX document adding an extension vocabulary uses the array form, so a
// string-only check declines a conformant SBOM.
//
// Do NOT reach for net/url or strings.EqualFold here. Both were tried and both
// made the two languages disagree: net/url reads "//host/path" as an authority
// where the WHATWG parser throws, and EqualFold folds U+017F against "s" where
// JavaScript's toLowerCase does not. Every clause below is plain byte work,
// pinned by the shared vector table.
func isSPDX3Context(v any) bool {
	return isSPDX3ContextAt(v, 0)
}

// maxContextDepth bounds the walk. JSON-LD nests contexts a handful deep at most;
// the bound exists so the two languages agree, since a JavaScript recursion of a
// few thousand frames throws where Go would not.
const maxContextDepth = 32

func isSPDX3ContextAt(v any, depth int) bool {
	if depth > maxContextDepth {
		return false
	}
	switch t := v.(type) {
	case string:
		return isSPDX3ContextURL(t)
	case []any:
		for _, el := range t {
			if isSPDX3ContextAt(el, depth+1) {
				return true
			}
		}
	case map[string]any:
		for _, el := range t {
			if isSPDX3ContextAt(el, depth+1) {
				return true
			}
		}
	}
	return false
}

// asciiLower lowercases A-Z and nothing else. strings.EqualFold applies Unicode
// simple case folding, which matches U+017F LATIN SMALL LETTER LONG S against
// "s"; JavaScript's toLowerCase applies Unicode lowercase mapping, which does
// not. Two stdlib case operations that look equivalent are not, so neither is
// used — RFC 3986 section 6.2.2.1 specifies ASCII case normalization for the
// scheme and host, which is what this does.
func asciiLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func isSPDX3ContextURL(s string) bool {
	// These exact bytes, not a category: see the doc comment above for what is and
	// is not covered, and the table for which of them a row isolates.
	if strings.ContainsAny(s, " \t\r\n\\%") || strings.Contains(s, "..") {
		return false
	}
	rest := ""
	for _, scheme := range [...]string{"https://", "http://"} {
		if len(s) >= len(scheme) && asciiLower(s[:len(scheme)]) == scheme {
			rest = s[len(scheme):]
			break
		}
	}
	if rest == "" {
		return false
	}
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return false
	}
	host := rest[:slash]
	if colon := strings.Index(host, ":"); colon >= 0 {
		host = host[:colon]
	}
	if asciiLower(host) != "spdx.org" {
		return false
	}
	version, ok := strings.CutPrefix(rest[slash:], "/rdf/")
	return ok && (strings.HasPrefix(version, "3.") || version == "3")
}

// IsBOMDocument reports whether input is a bill of materials at all. This is a
// WIDER question than DetectFormat, which answers which format ParseBom can
// normalize — and of the SPDX-3 profiles it normalizes the AI/dataset one only,
// so a plain SPDX 3 software-profile SBOM is a real BOM that DetectFormat
// declines.
//
// A caller that RECORDS A REFERENCE and never parses needs this one. Asking the
// narrower question left such an SBOM classified as foreign.
func IsBOMDocument(input any) bool {
	if DetectFormat(input) != nil {
		return true
	}
	obj := asRecord(input)
	return obj != nil && isSPDX3Context(obj["@context"])
}

// DetectFormat detects the BOM format of a parsed JSON value. ML wins over plain
// CycloneDX by precedence; returns nil when no supported format matches.
func DetectFormat(input any) *FormatDetection {
	if ml := DetectCycloneDXML(input); ml > 0 {
		return &FormatDetection{Format: FormatCycloneDXML, Confidence: ml}
	}
	if cdx := DetectCycloneDX(input); cdx > 0 {
		return &FormatDetection{Format: FormatCycloneDX, Confidence: cdx}
	}
	if spdx3 := DetectSPDX3(input); spdx3 > 0 {
		return &FormatDetection{Format: FormatSPDX3AI, Confidence: spdx3}
	}
	if sec := DetectSPDX3Security(input); sec > 0 {
		return &FormatDetection{Format: FormatSPDX3Security, Confidence: sec}
	}
	if spdx := DetectSPDX(input); spdx > 0 {
		return &FormatDetection{Format: FormatSPDX, Confidence: spdx}
	}
	return nil
}
