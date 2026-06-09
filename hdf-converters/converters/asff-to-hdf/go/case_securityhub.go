package asff

import (
	"strings"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/awsconfig"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// securityHubCase implements the heimdall2 case-security-hub.ts refinements
// for findings whose ProductArn is `product/aws/securityhub`. It overrides:
//   - productName: derive from ProductFields.StandardsControlArn so the
//     baseline title reads "Cis Aws Foundations Benchmark v1.2.0" instead
//     of the bare "securityhub - aws/securityhub" default.
//   - findingID:  prefer ProductFields.{ControlId,RuleId} over GeneratorId
//     so consolidation groups CIS rule 1.1 across all resources.
//   - findingImpact: bump INFORMATIONAL to MEDIUM when no supporting
//     standards docs are supplied — heimdall2 notes Security Hub mislabels
//     real findings as informational.
//   - findingNISTTags: resolve via awsconfig mapping when the finding's
//     RelatedAWSResources[0] is an AWS::Config::ConfigRule.
type securityHubCase struct{ defaultCase }

func (securityHubCase) productName(findings []map[string]any) string {
	if len(findings) == 0 {
		return "AWS Security Hub"
	}
	arn, _ := getString(findings[0], "ProductFields.StandardsControlArn")
	if arn == "" {
		// Fall back to the default-case productName which uses ProductArn.
		return defaultCase{}.productName(findings)
	}
	// arn shape:
	//   arn:aws:securityhub:us-east-1:123:control/cis-aws-foundations-benchmark/v/1.2.0/1.1
	// We want "Cis Aws Foundations Benchmark v1.2.0".
	segs := strings.Split(arn, "/")
	if len(segs) < 4 {
		return defaultCase{}.productName(findings)
	}
	standardSlug := segs[len(segs)-4]
	version := segs[len(segs)-2]
	return titleCase(strings.ReplaceAll(standardSlug, "-", " ")) + " v" + version
}

func (securityHubCase) findingID(finding map[string]any) string {
	if id, ok := getString(finding, "ProductFields.ControlId"); ok && id != "" {
		return id
	}
	if id, ok := getString(finding, "ProductFields.RuleId"); ok && id != "" {
		return id
	}
	// Fall back to the GeneratorId tail (heimdall2 parity).
	gen, _ := finding["GeneratorId"].(string)
	if idx := strings.LastIndex(gen, "/"); idx >= 0 {
		return gen[idx+1:]
	}
	return gen
}

func (securityHubCase) findingImpact(finding map[string]any) (float64, bool) {
	// SUPPRESSED still wins.
	if w, ok := finding["Workflow"].(map[string]any); ok {
		if status, _ := w["Status"].(string); status == "SUPPRESSED" {
			return 0.0, true
		}
	}
	sev, _ := finding["Severity"].(map[string]any)
	if sev == nil {
		return 0.0, true
	}
	label, _ := sev["Label"].(string)
	if label == "INFORMATIONAL" {
		// Heimdall2: when no supporting standards docs are supplied,
		// SecurityHub mislabels real findings as INFORMATIONAL —
		// bump to MEDIUM. We never accept supporting docs (heimdall2's
		// keywords feature isn't ported), so always bump.
		return asffSeverityToImpact["MEDIUM"], true
	}
	if v, ok := asffSeverityToImpact[label]; ok {
		return v, true
	}
	switch n := sev["Normalized"].(type) {
	case float64:
		return n / 100.0, true
	case int:
		return float64(n) / 100.0, true
	}
	return 0.0, true
}

func (securityHubCase) findingNISTTags(finding map[string]any) []string {
	related, ok := getString(finding, "ProductFields.RelatedAWSResources:0/type")
	if !ok || related != "AWS::Config::ConfigRule" {
		return nil
	}
	name, ok := getString(finding, "ProductFields.RelatedAWSResources:0/name")
	if !ok || name == "" {
		return nil
	}
	tags := awsconfig.NISTControls(name)
	if len(tags) == 0 {
		return nil
	}
	return tags
}

// titleCase capitalizes each whitespace-separated word.
func titleCase(s string) string {
	parts := strings.Fields(s)
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

// getString walks a dotted path through a map[string]any tree and returns the
// string at the leaf. Keys may contain dots themselves (ASFF ProductFields
// uses literal keys like `RelatedAWSResources:0/type`), so we try a longest-
// prefix match before falling back to dot splitting.
func getString(m map[string]any, path string) (string, bool) {
	if m == nil {
		return "", false
	}
	if v, ok := m[path].(string); ok {
		return v, true
	}
	// Try splitting on the first dot only and recursing.
	if idx := strings.Index(path, "."); idx >= 0 {
		head := path[:idx]
		rest := path[idx+1:]
		if nested, ok := m[head].(map[string]any); ok {
			return getString(nested, rest)
		}
	}
	// Fall back to the leaf key as a literal string lookup.
	return "", false
}

// Unused import guard — keep hdf import live for future result-side overrides
// in this case (none today; the field is referenced via embedded defaultCase).
var _ = hdf.Passed
