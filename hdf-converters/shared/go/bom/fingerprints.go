// BOM format fingerprints + DetectFormat dispatcher.
//
// Self-contained structural detectors for the three supported BOM formats.
// Detection precedence: an ML-BOM is a CycloneDX document with a
// machine-learning-model component, so the ML detector must win over the plain
// CycloneDX detector.

package bom

// FormatDetection reports a detected BOM format and a 0..1 confidence.
type FormatDetection struct {
	Format     string
	Confidence float64
}

// DetectCycloneDX reports confidence that input is a CycloneDX document
// (bomFormat === "CycloneDX"). Returns 0 or 1.
func DetectCycloneDX(input any) float64 {
	obj := asRecord(input)
	if obj != nil && obj["bomFormat"] == "CycloneDX" {
		return 1
	}
	return 0
}

// DetectCycloneDXML reports confidence that input is a CycloneDX ML-BOM: a
// CycloneDX document with at least one machine-learning-model component.
// Strictly more specific than plain CycloneDX. Returns 0 or 1.
func DetectCycloneDXML(input any) float64 {
	obj := asRecord(input)
	if obj == nil || obj["bomFormat"] != "CycloneDX" {
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
	if spdx := DetectSPDX(input); spdx > 0 {
		return &FormatDetection{Format: FormatSPDX, Confidence: spdx}
	}
	return nil
}
