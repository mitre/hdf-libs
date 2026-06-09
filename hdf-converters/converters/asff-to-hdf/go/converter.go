// Package asff converts AWS Security Finding Format (ASFF) JSON to HDF
// Results. Ported from heimdall2's libs/hdf-converters/src/asff-mapper/.
//
// This PR ships the Default and SecurityHub case handlers. The remaining
// special cases from heimdall2 (Prowler, Trivy, Inspector, GuardDuty,
// FirewallManager, CMS-InSpec, PreviouslyHDF) are tracked as a follow-up
// bead and slot into cases.go's dispatcher with no changes to this entry
// point.
package asff

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

const (
	generatorName = "asff-to-hdf"
	toolName      = "AWS Security Finding Format"
	toolFormat    = "JSON"
)

// ConvertAsffToHDF converts ASFF JSON to HDF Results. Accepts the standard
// `{"Findings": [...]}` envelope, a bare top-level array, or a single
// finding object — heimdall2 parity.
func ConvertAsffToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if err := shared.ValidateJSONSize(input, generatorName, 0); err != nil {
		return nil, err
	}
	if len(input) == 0 {
		return nil, fmt.Errorf("%s: empty input", generatorName)
	}

	findings, err := parseFindings(input)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", generatorName, err)
	}

	now := time.Now().UTC()
	requirements := buildRequirements(findings, now)

	if len(requirements) == 0 {
		// Step 4e: synthesize a passed placeholder so the document
		// validates (requirements.minItems = 1) without lying about
		// what the scanner did.
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"asff-no-findings",
				"ASFF scanned the AWS account and reported zero findings.",
				now,
			),
		}
	}

	baseline := buildBaseline(findings, requirements, input)
	components := buildComponents(findings)

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    generatorName,
		ConverterVersion: converterVersion,
		ToolName:         toolName,
		ToolFormat:       toolFormat,
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       components,
		Timestamp:        &now,
	}), nil
}

// parseFindings normalizes the three accepted input shapes into a slice of
// finding maps: `{"Findings": [...]}` (canonical), `[...]` (bare array), and
// `{...}` (single finding).
func parseFindings(input []byte) ([]map[string]any, error) {
	trimmed := []byte(strings.TrimSpace(string(input)))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	switch trimmed[0] {
	case '[':
		var arr []map[string]any
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("invalid JSON array: %w", err)
		}
		return arr, nil
	case '{':
		var obj map[string]any
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		if rawFindings, ok := obj["Findings"]; ok {
			// Standard `{"Findings": [...]}` envelope.
			arr, ok := rawFindings.([]any)
			if !ok {
				return nil, fmt.Errorf("findings field must be an array")
			}
			out := make([]map[string]any, 0, len(arr))
			for i, v := range arr {
				m, ok := v.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("findings[%d] is not an object", i)
				}
				out = append(out, m)
			}
			return out, nil
		}
		// Bare single finding.
		return []map[string]any{obj}, nil
	default:
		return nil, fmt.Errorf("input must be a JSON object or array")
	}
}

// buildRequirements turns each finding into a one-result requirement, then
// consolidates by requirement ID (heimdall2 parity: multiple findings against
// the same control group into one requirement with multiple results).
func buildRequirements(findings []map[string]any, now time.Time) []hdf.EvaluatedRequirement {
	if len(findings) == 0 {
		return nil
	}
	// Build (id, requirement, source-finding-json) tuples.
	type bucket struct {
		req         hdf.EvaluatedRequirement
		sourceJSONs []json.RawMessage
	}
	order := []string{}
	groups := map[string]*bucket{}

	for _, f := range findings {
		h := dispatch(f)
		req := buildRequirement(f, h, now)
		raw, _ := json.Marshal(f)
		if b, ok := groups[req.ID]; ok {
			b.req.Results = append(b.req.Results, req.Results...)
			b.req.Impact = max(b.req.Impact, req.Impact)
			b.req.Descriptions = mergeDescriptions(b.req.Descriptions, req.Descriptions)
			b.req.Refs = mergeRefs(b.req.Refs, req.Refs)
			b.req.Tags = mergeTags(b.req.Tags, req.Tags)
			b.sourceJSONs = append(b.sourceJSONs, raw)
		} else {
			groups[req.ID] = &bucket{req: req, sourceJSONs: []json.RawMessage{raw}}
			order = append(order, req.ID)
		}
	}

	out := make([]hdf.EvaluatedRequirement, 0, len(order))
	for _, id := range order {
		b := groups[id]
		// Heimdall2 puts the full original findings JSON into Code so
		// downstream tooling can inspect the raw source.
		codeBytes, _ := json.MarshalIndent(map[string]any{
			"Findings": rawMessagesToAny(b.sourceJSONs),
		}, "", "  ")
		code := string(codeBytes)
		b.req.Code = &code
		out = append(out, b.req)
	}
	return out
}

// buildRequirement maps one finding to an EvaluatedRequirement with exactly
// one Result. Consolidation merges these post-hoc.
func buildRequirement(finding map[string]any, h caseHandler, now time.Time) hdf.EvaluatedRequirement {
	id := h.findingID(finding)
	if id == "" {
		// Final fallback to keep the requirement.minItems guarantee.
		id = "asff-finding"
	}
	title := h.findingTitle(finding)
	descText, _ := finding["Description"].(string)
	descriptions := []hdf.Description{
		{Label: "default", Data: orDefault(descText, title)},
	}
	if rem := remediationText(finding); rem != "" {
		descriptions = append(descriptions, hdf.Description{Label: "fix", Data: rem})
	}

	impact, _ := h.findingImpact(finding)

	tags := buildTags(h.findingNISTTags(finding))

	refs := buildRefs(finding)
	startTime := finding["UpdatedAt"]
	startTimeStr, _ := startTime.(string)
	startTimeParsed := hdfutil.ParseTimestamp(startTimeStr)
	if startTimeStr == "" {
		startTimeParsed = now
	}

	status, _ := h.findingStatus(finding)
	resultMessage := statusMessage(finding, status)
	codeDesc := buildCodeDesc(finding)

	result := hdf.RequirementResult{
		Status:    status,
		CodeDesc:  codeDesc,
		StartTime: startTimeParsed,
	}
	if resultMessage != "" {
		result.Message = &resultMessage
	}

	req := hdf.EvaluatedRequirement{
		ID:                 id,
		Title:              hdfutil.Ptr(title),
		Descriptions:       descriptions,
		Impact:             impact,
		Tags:               tags,
		Refs:               refs,
		Results:            []hdf.RequirementResult{result},
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
	req.ControlType = shared.DeriveControlTypeFromTags(shared.NISTTagsFromMap(tags))
	return req
}

// buildBaseline assembles the single output baseline. Heimdall2 always emits
// one baseline per ASFF document; we follow suit.
func buildBaseline(findings []map[string]any, requirements []hdf.EvaluatedRequirement, input []byte) hdf.EvaluatedBaseline {
	handler := dispatchAll(findings)
	productName := "ASFF Findings"
	if len(findings) > 0 {
		productName = handler.productName(findings)
	}
	return hdf.EvaluatedBaseline{
		Name:            "ASFF",
		Title:           hdfutil.Ptr(productName),
		Requirements:    requirements,
		ResultsChecksum: shared.InputChecksum(input),
	}
}

// buildComponents derives a CloudAccount component from the first finding's
// AwsAccountId. If no account ID is present, returns no components — never
// emit a placeholder "Unknown" target (Step 4 Components convention).
func buildComponents(findings []map[string]any) []hdf.Component {
	if len(findings) == 0 {
		return nil
	}
	accountID, _ := findings[0]["AwsAccountId"].(string)
	if accountID == "" {
		return nil
	}
	return []hdf.Component{{
		Name: fmt.Sprintf("AWS Account %s", accountID),
		Type: hdf.CloudAccount,
		Labels: map[string]string{
			"account":  accountID,
			"provider": "aws",
		},
	}}
}

// ---- helpers ----

func buildTags(nist []string) map[string]any {
	if len(nist) == 0 {
		// No per-finding tags — DEFAULT_STATIC_CODE_ANALYSIS_NIST_TAGS is
		// reserved for the SA-11/RA-5 fallback bundle in heimdall2, but
		// since DeriveControlTypeFromTags explicitly gates that bundle
		// out, applying it would only produce a misleading controlType.
		// Leave tags empty rather than misclaim a NIST mapping.
		return map[string]any{}
	}
	tags := map[string]any{"nist": nist}
	cciTags := cci.NISTToCCI(nist)
	if len(cciTags) > 0 {
		tags["cci"] = cciTags
	}
	return tags
}

func buildRefs(finding map[string]any) []hdf.Reference {
	url, _ := finding["SourceUrl"].(string)
	if url == "" {
		return nil
	}
	return []hdf.Reference{{URL: hdfutil.Ptr(url)}}
}

func remediationText(finding map[string]any) string {
	rem, _ := finding["Remediation"].(map[string]any)
	if rem == nil {
		return ""
	}
	rec, _ := rem["Recommendation"].(map[string]any)
	if rec == nil {
		return ""
	}
	var parts []string
	if t, _ := rec["Text"].(string); t != "" {
		parts = append(parts, t)
	}
	if u, _ := rec["Url"].(string); u != "" {
		parts = append(parts, u)
	}
	return strings.Join(parts, "\n")
}

func buildCodeDesc(finding map[string]any) string {
	resources, _ := finding["Resources"].([]any)
	if len(resources) == 0 {
		return "Resources: []"
	}
	parts := make([]string, 0, len(resources))
	for _, r := range resources {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := rm["Type"].(string)
		id, _ := rm["Id"].(string)
		part := fmt.Sprintf("Type: %s, Id: %s", typ, id)
		if p, _ := rm["Partition"].(string); p != "" {
			part += fmt.Sprintf(", Partition: %s", p)
		}
		if reg, _ := rm["Region"].(string); reg != "" {
			part += fmt.Sprintf(", Region: %s", reg)
		}
		parts = append(parts, part)
	}
	return "Resources: [" + strings.Join(parts, ", ") + "]"
}

// statusMessage returns a per-result message, mirroring heimdall2's
// per-status decision tree (failed/passed → reason text; warning/missing →
// emitted via SkipMessage which we collapse into Message for HDF since
// HDF lacks a SkipMessage field).
func statusMessage(finding map[string]any, status hdf.ResultStatus) string {
	reason := statusReason(finding)
	if reason == "" {
		return ""
	}
	switch status {
	case hdf.Passed, hdf.Failed, hdf.NotReviewed:
		return reason
	}
	return ""
}

func statusReason(finding map[string]any) string {
	c, _ := finding["Compliance"].(map[string]any)
	if c == nil {
		return ""
	}
	reasons, _ := c["StatusReasons"].([]any)
	if len(reasons) == 0 {
		return ""
	}
	parts := make([]string, 0, len(reasons))
	for _, r := range reasons {
		rm, _ := r.(map[string]any)
		if rm == nil {
			continue
		}
		desc, _ := rm["Description"].(string)
		code, _ := rm["ReasonCode"].(string)
		switch {
		case desc != "" && code != "":
			parts = append(parts, code+": "+desc)
		case desc != "":
			parts = append(parts, desc)
		case code != "":
			parts = append(parts, code)
		}
	}
	return strings.Join(parts, "; ")
}

// ---- merging helpers used by consolidation ----

func mergeDescriptions(a, b []hdf.Description) []hdf.Description {
	seen := map[string]bool{}
	out := make([]hdf.Description, 0, len(a)+len(b))
	for _, d := range append(a, b...) {
		key := d.Label + "\x00" + d.Data
		if seen[key] || d.Data == "" {
			continue
		}
		seen[key] = true
		out = append(out, d)
	}
	return out
}

func mergeRefs(a, b []hdf.Reference) []hdf.Reference {
	seen := map[string]bool{}
	out := make([]hdf.Reference, 0, len(a)+len(b))
	for _, r := range append(a, b...) {
		if r.URL == nil {
			continue
		}
		if seen[*r.URL] {
			continue
		}
		seen[*r.URL] = true
		out = append(out, r)
	}
	return out
}

func mergeTags(a, b map[string]any) map[string]any {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	out := map[string]any{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if existing, ok := out[k]; ok {
			out[k] = unionAny(existing, v)
		} else {
			out[k] = v
		}
	}
	return out
}

func unionAny(x, y any) any {
	xs, xok := x.([]string)
	ys, yok := y.([]string)
	if xok && yok {
		seen := map[string]bool{}
		var out []string
		for _, s := range append(xs, ys...) {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
		return out
	}
	return x
}

func rawMessagesToAny(raws []json.RawMessage) []any {
	out := make([]any, 0, len(raws))
	for _, r := range raws {
		var v any
		_ = json.Unmarshal(r, &v)
		out = append(out, v)
	}
	return out
}

func orDefault(s, fallback string) string {
	if strings.TrimSpace(s) != "" {
		return s
	}
	if strings.TrimSpace(fallback) != "" {
		return fallback
	}
	return "ASFF finding"
}
