// Shared BOM normalization: ParseBom / BuildBom / DetectFormat dispatch and the
// cross-format helpers (object guards, license cleaning, purl handling).
// Format-specific extraction lives in cyclonedx.go / spdx.go / mlbom.go.

package bom

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

const converterName = "bom-parser"

// maxPackages caps the normalized package inventory (parity with the TS
// limitArrayWithWarning default used by the shared converterutil).
const maxPackages = 100000

// spdxNullLicenses are SPDX sentinels that mean "no license", filtered out of
// normalized output.
var spdxNullLicenses = map[string]bool{"noassertion": true, "none": true}

// ParseResult mirrors the TS { format, normalized } shape.
type ParseResult struct {
	Format     string
	Normalized *NormalizedBom
}

// BuildBomParts are the parts accepted by BuildBom. Only the extension matching
// BOMType is kept.
type BuildBomParts struct {
	BOMType  BOMType
	Format   string
	Packages []SBOMPackage
	Model    *AIModelBOMExtension
	Dataset  *DatasetBOMExtension
	Ref      *string
	Document map[string]any
	UniqueID *string
	Hashes   []Checksum
	License  *string
}

// asRecord narrows an unknown value to a map (not array, not null).
func asRecord(value any) map[string]any {
	if m, ok := value.(map[string]any); ok {
		return m
	}
	return nil
}

// asString narrows an unknown value to a non-empty string, returning "" when
// absent (mirrors the TS asString returning undefined).
func asString(value any) string {
	if s, ok := value.(string); ok && len(s) > 0 {
		return s
	}
	return ""
}

// stringifyScalar renders a heterogeneous scalar BOM value (metric value,
// SPDX DictionaryEntry value) to the SAME string the TS side produces via
// String(value) — a hard TS↔Go parity requirement. Strings pass through;
// JSON numbers (float64) are formatted to match JS Number#toString exactly
// (see jsNumberToString); other scalars use Go's default %v, which already
// agrees with JS String() for booleans (true/false).
func stringifyScalar(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return jsNumberToString(x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

// jsNumberToString formats a float64 to the exact string JavaScript's
// Number#toString (radix 10) / String(n) produces. Go's strconv formatters
// diverge from JS in exponent thresholds and padding (e.g. 1e-6 -> "1e-06" not
// "0.000001", 1e-7 -> "1e-07" not "1e-7", 1234567 -> "1.234567e+06" not
// "1234567"), so this reimplements the ECMAScript Number::toString algorithm:
// take the shortest round-tripping digit string and lay it out per the spec's
// exponent rules. Verified byte-identical to Node's String() across integer,
// decimal, small/large exponent, and denormal values.
func jsNumberToString(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		return "0"
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	// Shortest scientific representation: "d.dddde±XX".
	mantissa, expStr, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	exp, _ := strconv.Atoi(expStr)
	digits := strings.Replace(mantissa, ".", "", 1)
	k := len(digits) // number of significant digits
	n := exp + 1     // position of the decimal point (ECMAScript's n)

	var b strings.Builder
	b.WriteString(sign)
	switch {
	case k <= n && n <= 21:
		b.WriteString(digits)
		b.WriteString(strings.Repeat("0", n-k))
	case 0 < n && n <= 21:
		b.WriteString(digits[:n])
		b.WriteByte('.')
		b.WriteString(digits[n:])
	case -6 < n && n <= 0:
		b.WriteString("0.")
		b.WriteString(strings.Repeat("0", -n))
		b.WriteString(digits)
	default:
		if k == 1 {
			b.WriteString(digits)
		} else {
			b.WriteByte(digits[0])
			b.WriteByte('.')
			b.WriteString(digits[1:])
		}
		b.WriteByte('e')
		e := n - 1
		if e >= 0 {
			b.WriteByte('+')
		} else {
			b.WriteByte('-')
			e = -e
		}
		b.WriteString(strconv.Itoa(e))
	}
	return b.String()
}

// cleanLicense returns an SPDX license string unless it is a NOASSERTION/NONE
// sentinel; returns "" for absent/sentinel values.
func cleanLicense(value any) string {
	s := asString(value)
	if s == "" {
		return ""
	}
	if spdxNullLicenses[strings.ToLower(strings.TrimSpace(s))] {
		return ""
	}
	return s
}

// strPtr returns a pointer to s, or nil when s is empty.
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// enrichFromPurl fills a package's missing name/version from its purl when
// parseable. Never overwrites values the source BOM already provided (e.g. an
// SPDX versionInfo is authoritative over a purl whose @segment is a git commit).
func enrichFromPurl(pkg *SBOMPackage) {
	if pkg.Purl == nil || *pkg.Purl == "" {
		return
	}
	parsed := hdfutil.ParsePurl(*pkg.Purl)
	if parsed == nil {
		return
	}
	if pkg.Version == nil && parsed.Version != nil {
		pkg.Version = parsed.Version
	}
	if pkg.Name == "" && parsed.Name != "" {
		pkg.Name = parsed.Name
	}
}

// BuildBom assembles a schema-valid BillOfMaterials from normalized parts,
// enforcing the three-tier discipline: the packages/model/dataset extension is
// kept only when it matches BOMType; a mismatched extension is silently dropped
// (the schema forbids it, so carrying it would produce invalid output).
func BuildBom(parts BuildBomParts) *BillOfMaterials {
	bom := &BillOfMaterials{BOMType: parts.BOMType, Format: parts.Format}

	if parts.Ref != nil {
		bom.Ref = parts.Ref
	}
	if parts.Document != nil {
		bom.Document = parts.Document
	}
	if parts.UniqueID != nil {
		bom.UniqueID = parts.UniqueID
	}
	if len(parts.Hashes) > 0 {
		bom.Hashes = parts.Hashes
	}
	if parts.License != nil {
		bom.License = parts.License
	}

	if parts.BOMType == BOMTypeSbom && parts.Packages != nil {
		bom.Packages = parts.Packages
	}
	if parts.BOMType == BOMTypeAIModel && parts.Model != nil {
		bom.Model = parts.Model
	}
	if parts.BOMType == BOMTypeDataset && parts.Dataset != nil {
		bom.Dataset = parts.Dataset
	}

	return bom
}

// ParseBom detects and parses a BOM document into normalized form. It validates
// input size FIRST (security boundary), then dispatches on the detected format.
// Returns an error on oversized or undetectable input.
func ParseBom(input []byte) (*ParseResult, error) {
	if err := shared.ValidateJSONSize(input, converterName, 0); err != nil {
		return nil, err
	}
	var obj any
	if err := json.Unmarshal(input, &obj); err != nil {
		return nil, fmt.Errorf("%s: parse JSON: %w", converterName, err)
	}
	detected := DetectFormat(obj)
	if detected == nil {
		return nil, errors.New(
			"bom-parser: could not detect a supported BOM format (expected CycloneDX or SPDX JSON)",
		)
	}
	record := asRecord(obj)
	if record == nil {
		record = map[string]any{}
	}
	switch detected.Format {
	case FormatCycloneDXML:
		return &ParseResult{Format: detected.Format, Normalized: ParseMLBOM(record)}, nil
	case FormatCycloneDX:
		return &ParseResult{Format: detected.Format, Normalized: ParseCycloneDX(record)}, nil
	case FormatSPDX:
		return &ParseResult{Format: detected.Format, Normalized: ParseSPDX(record)}, nil
	case FormatSPDX3AI:
		// SPDX-3 is multi-subject; ParseBom's single-BOM contract returns the
		// first subject's BOM. The full multi-subject consumer is ParseSPDX3.
		result := ParseSPDX3(record)
		if len(result.Subjects) == 0 {
			return nil, fmt.Errorf("%s: SPDX-3 document carries no AI/dataset subjects", converterName)
		}
		return &ParseResult{Format: detected.Format, Normalized: result.Subjects[0].Bom}, nil
	default:
		return nil, fmt.Errorf("%s: unhandled format %q", converterName, detected.Format)
	}
}

// normalized wraps a BuildBom result in a NormalizedBom (the relational graph
// scaffolding stays nil until a relational format is normalized).
func normalized(bom *BillOfMaterials) *NormalizedBom {
	return &NormalizedBom{BillOfMaterials: *bom}
}
