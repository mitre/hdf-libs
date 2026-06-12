package asff

import (
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// defaultCase implements the canonical ASFF → HDF mapping per the AWS
// AwsSecurityFinding specification, with no source-product-specific
// refinements. Every other case embeds these defaults via the dispatcher's
// "handled=false" fallback.
type defaultCase struct{}

// asffSeverityToImpact mirrors heimdall2's IMPACT_MAPPING for the canonical
// Severity.Label values.
var asffSeverityToImpact = map[string]float64{
	"CRITICAL":      0.9,
	"HIGH":          0.7,
	"MEDIUM":        0.5,
	"LOW":           0.3,
	"INFORMATIONAL": 0.0,
}

func (defaultCase) productName(findings []map[string]any) string {
	if len(findings) == 0 {
		return "ASFF Findings"
	}
	productArn, _ := findings[0]["ProductArn"].(string)
	// Pull last segment of ProductArn (after final ':'), then split by '/'.
	// Heimdall2: `${productInfo[1]} - ${productInfo[2]}`.
	parts := strings.Split(productArn, ":")
	if len(parts) == 0 {
		return "ASFF Findings"
	}
	tail := parts[len(parts)-1]
	segs := strings.Split(tail, "/")
	if len(segs) >= 3 {
		return segs[1] + " - " + segs[2]
	}
	return "ASFF Findings"
}

func (defaultCase) findingID(finding map[string]any) string {
	id, _ := finding["GeneratorId"].(string)
	return id
}

func (defaultCase) findingTitle(finding map[string]any) string {
	t, _ := finding["Title"].(string)
	return t
}

func (defaultCase) findingImpact(finding map[string]any) (float64, bool) {
	// SUPPRESSED workflow overrides label to 0 — heimdall2 parity.
	if w, ok := finding["Workflow"].(map[string]any); ok {
		if status, _ := w["Status"].(string); status == "SUPPRESSED" {
			return 0.0, true
		}
	}
	sev, _ := finding["Severity"].(map[string]any)
	if sev == nil {
		return 0.0, true
	}
	if label, _ := sev["Label"].(string); label != "" {
		if v, ok := asffSeverityToImpact[label]; ok {
			return v, true
		}
	}
	// Fallback to Normalized / 100.
	switch n := sev["Normalized"].(type) {
	case float64:
		return n / 100.0, true
	case int:
		return float64(n) / 100.0, true
	}
	return 0.0, true
}

// findingNISTTags returns no per-finding tags by default — the caller falls
// back to DEFAULT_STATIC_CODE_ANALYSIS_NIST_TAGS via shared helpers.
func (defaultCase) findingNISTTags(finding map[string]any) []string {
	return nil
}

func (defaultCase) findingStatus(finding map[string]any) (hdf.ResultStatus, bool) {
	compliance, _ := finding["Compliance"].(map[string]any)
	if compliance == nil {
		// Heimdall2: missing Compliance → failed.
		return hdf.Failed, true
	}
	switch compliance["Status"] {
	case "PASSED":
		return hdf.Passed, true
	case "FAILED":
		return hdf.Failed, true
	case "WARNING":
		// Heimdall2 maps to Skipped (HDF NotReviewed).
		return hdf.NotReviewed, true
	case "NOT_AVAILABLE":
		return hdf.NotReviewed, true
	default:
		return hdf.Error, true
	}
}
