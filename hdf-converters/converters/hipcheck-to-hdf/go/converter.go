// Package hipcheck converts MITRE Hipcheck `hc check --format json` reports to HDF.
package hipcheck

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hipcheckmap "github.com/mitre/hdf-libs/hdf-mappings/go/v3/hipcheck"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// Report is the top-level Hipcheck `hc check --format json` output.
type Report struct {
	RepoName        string            `json:"repo_name"`
	RepoOwner       *string           `json:"repo_owner"`
	RepoHead        string            `json:"repo_head"`
	HipcheckVersion string            `json:"hipcheck_version"`
	AnalyzedAt      string            `json:"analyzed_at"`
	Passing         []Analysis        `json:"passing"`
	Failing         []Analysis        `json:"failing"`
	Errored         []ErroredAnalysis `json:"errored"`
	Recommendation  Recommendation    `json:"recommendation"`
}

// Analysis is one passing/failing analysis. (The constant "analysis":"Analysis"
// serde tag field Hipcheck emits is intentionally not modeled.)
type Analysis struct {
	Name       string   `json:"name"`
	Passed     bool     `json:"passed"`
	PolicyExpr string   `json:"policy_expr"`
	FinalValue *string  `json:"final_value"`
	Message    string   `json:"message"`
	Concerns   []string `json:"concerns,omitempty"`
}

// ErroredAnalysis is one analysis that failed to run. Its `analysis` field holds
// the analysis name (unlike passing/failing, where it is the constant tag).
type ErroredAnalysis struct {
	Name  string      `json:"name"`
	Error ErrorReport `json:"error"`
}

// ErrorReport is Hipcheck's recursive error chain.
type ErrorReport struct {
	Msg    string       `json:"msg"`
	Source *ErrorReport `json:"source,omitempty"`
}

// Recommendation is the overall verdict. `reason` is polymorphic: null, the
// string "Policy", or an object {"FailedAnalyses":[...]}.
type Recommendation struct {
	Kind       string          `json:"kind"`
	Reason     json.RawMessage `json:"reason"`
	RiskScore  float64         `json:"risk_score"`
	RiskPolicy string          `json:"risk_policy"`
}

// ConvertHipcheckToHDF converts a Hipcheck JSON report to HDF Results.
func ConvertHipcheckToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if err := shared.ValidateJSONSize(input, "hipcheck", 0); err != nil {
		return nil, fmt.Errorf("hipcheck: %w", err)
	}
	if len(strings.TrimSpace(string(input))) == 0 {
		return nil, fmt.Errorf("hipcheck: empty input")
	}

	var report Report
	if err := json.Unmarshal(input, &report); err != nil {
		return nil, fmt.Errorf("hipcheck: failed to parse report: %w", err)
	}
	if report.HipcheckVersion == "" && report.RepoName == "" {
		return nil, fmt.Errorf("hipcheck: input does not look like a Hipcheck report")
	}

	startTime := hdfutil.ParseTimestamp(report.AnalyzedAt)
	if startTime.IsZero() {
		startTime = time.Now().UTC()
	}

	requirements := make([]hdf.EvaluatedRequirement, 0,
		len(report.Passing)+len(report.Failing)+len(report.Errored))
	for _, a := range report.Passing {
		requirements = append(requirements, buildAnalysisRequirement(a, hdf.Passed, startTime))
	}
	for _, a := range report.Failing {
		requirements = append(requirements, buildAnalysisRequirement(a, hdf.Failed, startTime))
	}
	for _, e := range report.Errored {
		requirements = append(requirements, buildErroredRequirement(e, startTime))
	}

	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"hipcheck-no-findings",
				fmt.Sprintf("Hipcheck analyzed %s and reported zero analyses.", repoIdent(report)),
				startTime,
			),
		}
	}

	summary := buildSummary(report.Recommendation)
	title := fmt.Sprintf("Hipcheck analysis of %s @ %s", repoIdent(report), report.RepoHead)

	baseline := hdf.EvaluatedBaseline{
		Name:            "Hipcheck Scan",
		Title:           &title,
		Summary:         &summary,
		Requirements:    requirements,
		ResultsChecksum: shared.InputChecksum(input),
	}

	var components []hdf.Component
	if ident := repoIdent(report); ident != "" {
		components = []hdf.Component{{Name: ident, Type: hdf.Repository}}
	}

	now := time.Now().UTC()
	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "hipcheck-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Hipcheck",
		ToolVersion:      report.HipcheckVersion,
		ToolFormat:       "JSON",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       components,
		Timestamp:        &now,
	}), nil
}

// repoIdent returns "owner/name" when both are present, else whichever is
// non-empty (never a bare "owner/" or "/name").
func repoIdent(r Report) string {
	owner := ""
	if r.RepoOwner != nil {
		owner = *r.RepoOwner
	}
	if owner != "" && r.RepoName != "" {
		return owner + "/" + r.RepoName
	}
	if r.RepoName != "" {
		return r.RepoName
	}
	return owner
}

// analysisTags builds NIST/CCI tags for an analysis name via the hipcheck mapping.
func analysisTags(name string) (map[string]interface{}, []string) {
	nist := hipcheckmap.NISTControls(name)
	if len(nist) == 0 {
		return shared.BuildNISTCCITags(nil, nil), nil
	}
	return shared.BuildNISTCCITags(nist, cci.NISTToCCI(nist)), nist
}

func buildAnalysisRequirement(a Analysis, status hdf.ResultStatus, startTime time.Time) hdf.EvaluatedRequirement {
	tags, nist := analysisTags(a.Name)

	descriptions := []hdf.Description{{Label: "default", Data: a.Message}}
	if a.PolicyExpr != "" {
		descriptions = append(descriptions, hdf.Description{Label: "check", Data: a.PolicyExpr})
	}

	message := a.Message
	if len(a.Concerns) > 0 {
		message = message + "\nConcerns:\n- " + strings.Join(a.Concerns, "\n- ")
	}

	title := a.Name
	req := hdf.EvaluatedRequirement{
		ID:                 a.Name,
		Title:              &title,
		Impact:             0.5,
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       descriptions,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
		Results: []hdf.RequirementResult{{
			Status:    status,
			CodeDesc:  a.PolicyExpr,
			Message:   &message,
			StartTime: startTime,
		}},
	}
	return req
}

func buildErroredRequirement(e ErroredAnalysis, startTime time.Time) hdf.EvaluatedRequirement {
	tags, nist := analysisTags(e.Name)
	msg := flattenError(&e.Error)
	title := e.Name

	return hdf.EvaluatedRequirement{
		ID:                 e.Name,
		Title:              &title,
		Impact:             0.5,
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       []hdf.Description{{Label: "default", Data: msg}},
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
		Results: []hdf.RequirementResult{{
			Status:    hdf.Error,
			Message:   &msg,
			StartTime: startTime,
		}},
	}
}

// flattenError renders Hipcheck's recursive error chain as "msg: source: ...".
func flattenError(e *ErrorReport) string {
	if e == nil {
		return "unknown error"
	}
	parts := []string{}
	for cur := e; cur != nil; cur = cur.Source {
		if cur.Msg != "" {
			parts = append(parts, cur.Msg)
		}
	}
	if len(parts) == 0 {
		return "unknown error"
	}
	return strings.Join(parts, ": ")
}

// buildSummary renders the overall recommendation as baseline summary prose.
func buildSummary(rec Recommendation) string {
	base := fmt.Sprintf("Hipcheck recommendation: %s (risk score %s, policy '%s').",
		rec.Kind, formatScore(rec.RiskScore), rec.RiskPolicy)
	if !strings.EqualFold(rec.Kind, "Investigate") {
		return base
	}
	if suffix := investigateReason(rec.Reason); suffix != "" {
		return base + " " + suffix
	}
	return base
}

// investigateReason decodes the polymorphic `reason` into a sentence, or "".
func investigateReason(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return ""
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		if asString == "Policy" {
			return "Investigation triggered because the risk score exceeded the policy threshold."
		}
		return "Investigation reason: " + asString + "."
	}
	var obj struct {
		FailedAnalyses []string `json:"FailedAnalyses"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && len(obj.FailedAnalyses) > 0 {
		return "Investigation forced by failed analyses: " + strings.Join(obj.FailedAnalyses, ", ") + "."
	}
	return ""
}

// formatScore renders a risk score without trailing zeros (0.42, 0.33, 0).
func formatScore(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}
