package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
)

// complianceInput is the hdf_compliance argument surface: a source, an optional
// grouping mode, and an optional threshold (inline object or path).
type complianceInput struct {
	Source    handle.Source   `json:"source" jsonschema:"document as {path} or {handle}"`
	GroupBy   string          `json:"groupBy,omitempty" jsonschema:"baseline | severity | nistFamily"`
	Threshold *thresholdInput `json:"threshold,omitempty" jsonschema:"threshold spec: {path} to a YAML/JSON file, or {inline} object"`
}

// thresholdInput is the "inline object OR a path" union for a threshold spec.
type thresholdInput struct {
	Path   string         `json:"path,omitempty" jsonschema:"path to a YAML/JSON threshold file under HDF_MCP_ROOT"`
	Inline map[string]any `json:"inline,omitempty" jsonschema:"inline threshold spec (compliance/passed/failed/... bounds)"`
}

// complianceOutput is the hdf_compliance result: percent compliance, the
// status×severity rollup, the §3 agent-override detective block, an optional
// grouped rollup, and an optional threshold verdict.
type complianceOutput struct {
	Handle              string  `json:"handle"`
	DocType             string  `json:"docType"`
	EngineSchemaVersion string  `json:"engineSchemaVersion"`
	Compliance          float64 `json:"compliance"`
	// Counts holds the status × severity StatusCounts as status → severity → int.
	// This reflects to object→object→integer (value-typed) — richer than a bare
	// additionalProperties:true, yet far cheaper than the fully named-key
	// StatusCounts schema, which measured ~2x the per-tool token ceiling (lj0g.3).
	// The status keys are SAF vocabulary (skipped/no_impact); see the tool
	// description for the schema-vocabulary mapping.
	Counts           map[string]map[string]int `json:"counts"`
	AgentOverrides   agentOverrideSummary      `json:"agentOverrides"`
	GroupBy          string                    `json:"groupBy,omitempty"`
	Groups           []groupRollup             `json:"groups,omitempty"`
	ThresholdVerdict *thresholdVerdict         `json:"thresholdVerdict,omitempty"`
	Truncated        bool                      `json:"truncated,omitempty"`
	Notice           string                    `json:"notice,omitempty"`
}

// agentOverrideSummary is the detective surface of §3: how many overrides on the
// results file are agent-attributed, and the compliance points those overrides
// account for (effective compliance with them, minus with them stripped).
type agentOverrideSummary struct {
	Count           int     `json:"count"`
	ComplianceDelta float64 `json:"complianceDelta"`
}

type thresholdVerdict struct {
	Pass     bool     `json:"pass"`
	Failures []string `json:"failures"`
}

type groupRollup struct {
	Group      string  `json:"group"`
	Compliance float64 `json:"compliance"`
	// Counts holds the StatusCounts as status → severity → int (see complianceOutput.Counts).
	Counts map[string]map[string]int `json:"counts"`
}

// RegisterCompliance registers the hdf_compliance tool on the server.
func RegisterCompliance(s *sdkmcp.Server, ldr *loader.Loader) {
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name: "hdf_compliance",
		Description: "Compute aggregate percent compliance and status/severity rollups (by effective status: " +
			"impact-0 is Not Applicable and excluded from the denominator, overrides honored) for an HDF results " +
			"document, with an optional grouped breakdown and threshold verdict. counts is aggregate — for " +
			"per-requirement status use hdf_query. counts uses SAF threshold-file keys: skipped = notReviewed, " +
			"no_impact = notApplicable. The agentOverrides block is the detective surface: agent-attributed " +
			"override count and the compliance delta they account for.",
		Annotations: appmcp.ReadOnly(),
	}, hdfCompliance(ldr))
}

func hdfCompliance(ldr *loader.Loader) sdkmcp.ToolHandlerFor[complianceInput, complianceOutput] {
	return func(_ context.Context, _ *sdkmcp.CallToolRequest, in complianceInput) (*sdkmcp.CallToolResult, complianceOutput, error) {
		resolved, terr := resolveSource(in.Source, ldr, "source")
		if terr != nil {
			return toolError(terr), errorComplianceOutput(), nil
		}
		encoded, err := handle.Encode(resolved.Handle)
		if err != nil {
			return nil, errorComplianceOutput(), fmt.Errorf("encoding handle: %w", err)
		}

		toResults, ok := queryDispatch[resolved.Load.DocType]
		if !ok {
			e := mcperr.New(mcperr.WrongDocType,
				fmt.Sprintf("hdf_compliance rolls up requirements in results and baseline documents; a %s document has no requirements to score", resolved.Load.DocType),
				map[string]any{"docType": resolved.Load.DocType}).
				WithNextCall("call hdf_inspect to view this document's structure (hdf_compliance is results/baseline only)")
			return toolError(e), errorComplianceOutput(), nil
		}
		if !resolved.Load.Valid {
			e := mcperr.New(mcperr.SchemaInvalid,
				fmt.Sprintf("the document is %s but failed schema validation, so it cannot be scored", resolved.Load.DocType),
				map[string]any{"docType": resolved.Load.DocType})
			return toolError(e), errorComplianceOutput(), nil
		}

		results := toResults(resolved.Load)
		counts := countByEffectiveStatus(results)
		out := complianceOutput{
			Handle:              encoded,
			DocType:             resolved.Load.DocType,
			EngineSchemaVersion: resolved.Handle.EngineSchemaVersion,
			Compliance:          hdfengine.CalculateCompliance(counts),
			Counts:              countsToNestedInt(counts),
			AgentOverrides: agentOverrideSummary{
				Count:           hdfengine.AgentOverrideCount(results),
				ComplianceDelta: agentComplianceDelta(results),
			},
		}

		if in.GroupBy != "" {
			groups, gerr := groupedRollups(results, in.GroupBy)
			if gerr != nil {
				return toolError(gerr), errorComplianceOutput(), nil
			}
			out.GroupBy = in.GroupBy
			out.Groups = groups
		}

		if in.Threshold != nil {
			cfg, therr := resolveThreshold(in.Threshold)
			if therr != nil {
				return toolError(therr), errorComplianceOutput(), nil
			}
			if cfg != nil {
				controlMap := hdfengine.MapControlIDsByStatus(results, effectiveStatus)
				failures := hdfengine.ValidateThresholds(cfg, counts, out.Compliance, controlMap)
				out.ThresholdVerdict = &thresholdVerdict{Pass: len(failures) == 0, Failures: failures}
			}
		}

		boundComplianceResponse(&out)
		return nil, out, nil
	}
}

// agentComplianceDelta reports the compliance points agent-attributed overrides
// account for: effective compliance honoring all overrides, minus effective
// compliance with the agent-attributed overrides stripped (§3). Both sides count
// by effective status via the shared engine primitive with an injected resolver;
// the tool re-implements no counting.
func agentComplianceDelta(results hdf.HDFResults) float64 {
	withAgent := hdfengine.CalculateCompliance(countByEffectiveStatus(results))
	withoutAgent := hdfengine.CalculateCompliance(hdfengine.CountControlsByStatus(results, effectiveStatusExcludingAgent))
	return math.Round((withAgent-withoutAgent)*100) / 100
}

// errorComplianceOutput is the structured output returned alongside a toolError.
// counts is a required, non-nullable object in the output schema (value-typed,
// lj0g.3), so a zero-value complianceOutput{} (nil counts → JSON null) fails the
// SDK's output-schema validation and masks the real toolError (lj0g.10). An
// empty (non-nil) counts map serializes as {} and validates.
func errorComplianceOutput() complianceOutput {
	return complianceOutput{Counts: map[string]map[string]int{}}
}

// countsToNestedInt projects StatusCounts to a status → severity → int map, so
// the output field reflects to a value-typed object→object→integer schema
// (richer than additionalProperties:true, within the per-tool token ceiling —
// lj0g.3). SeverityCounts' omitempty drops zero severity buckets; total is
// always present.
func countsToNestedInt(c *hdfengine.StatusCounts) map[string]map[string]int {
	b, err := json.Marshal(c)
	if err != nil {
		return map[string]map[string]int{}
	}
	var m map[string]map[string]int
	if json.Unmarshal(b, &m) != nil {
		return map[string]map[string]int{}
	}
	return m
}

// effectiveStatusExcludingAgent resolves a requirement's effective status after
// dropping its agent-attributed overrides, reusing the shared status computation
// (composed, not forked — the same primitive effectiveStatus uses).
func effectiveStatusExcludingAgent(control hdf.EvaluatedRequirement) string {
	kept := make([]hdf.StatusOverride, 0, len(control.StatusOverrides))
	for _, o := range control.StatusOverrides {
		if o.AppliedBy.Type != hdf.Agent {
			kept = append(kept, o)
		}
	}
	control.StatusOverrides = kept
	return hdfutil.ComputeEffectiveStatus(shared.RequirementStatusInput(control), time.Time{})
}

// groupedRollups partitions the result set by the requested mode and scores each
// partition with the shared engine counting/compliance functions.
func groupedRollups(results hdf.HDFResults, mode string) ([]groupRollup, *mcperr.Error) {
	partitions, gerr := partitionResults(results, mode)
	if gerr != nil {
		return nil, gerr
	}
	rollups := make([]groupRollup, 0, len(partitions))
	for key, sub := range partitions {
		counts := countByEffectiveStatus(sub)
		rollups = append(rollups, groupRollup{
			Group:      key,
			Compliance: hdfengine.CalculateCompliance(counts),
			Counts:     countsToNestedInt(counts),
		})
	}
	sort.Slice(rollups, func(i, j int) bool { return rollups[i].Group < rollups[j].Group })
	return rollups, nil
}

// partitionResults splits a result set into named sub-result-sets by group mode.
// Each partition is a full HDFResults so the shared engine scores it unchanged.
func partitionResults(results hdf.HDFResults, mode string) (map[string]hdf.HDFResults, *mcperr.Error) {
	switch mode {
	case "baseline":
		out := map[string]hdf.HDFResults{}
		for i := range results.Baselines {
			b := results.Baselines[i]
			out[b.Name] = hdf.HDFResults{Baselines: []hdf.EvaluatedBaseline{b}}
		}
		return out, nil
	case "severity":
		return partitionBy(results, func(req hdf.EvaluatedRequirement) []string {
			return []string{groupSeverity(req)}
		}), nil
	case "nistFamily":
		return partitionBy(results, nistFamilies), nil
	default:
		return nil, mcperr.Arg(fmt.Sprintf("unknown groupBy %q", mode),
			"use groupBy = baseline, severity, or nistFamily (or omit it)")
	}
}

// partitionBy buckets each requirement into every key keyOf returns (a
// requirement can land in several nistFamily groups), each bucket a single-
// baseline HDFResults the engine scores directly.
func partitionBy(results hdf.HDFResults, keyOf func(hdf.EvaluatedRequirement) []string) map[string]hdf.HDFResults {
	buckets := map[string][]hdf.EvaluatedRequirement{}
	for i := range results.Baselines {
		for j := range results.Baselines[i].Requirements {
			req := results.Baselines[i].Requirements[j]
			for _, key := range keyOf(req) {
				buckets[key] = append(buckets[key], req)
			}
		}
	}
	out := make(map[string]hdf.HDFResults, len(buckets))
	for key, reqs := range buckets {
		out[key] = hdf.HDFResults{Baselines: []hdf.EvaluatedBaseline{{Name: key, Requirements: reqs}}}
	}
	return out
}

// groupSeverity is the severity group key for a requirement — the single
// canonical rule (hdfengine.DeriveSeverity: explicit STIG tag first, impact-
// derived fallback with the zero band normalized to "none") that hdf_query rows
// and the compliance counts also use, so no surface reports one requirement at
// two severities.
func groupSeverity(req hdf.EvaluatedRequirement) string {
	return hdfengine.DeriveSeverity(req.Impact, req.Severity)
}

// nistFamilies returns the distinct NIST control families a requirement maps to
// (e.g. AC-2 and AC-6 → "AC"); requirements with no NIST tag group under
// "unmapped".
func nistFamilies(req hdf.EvaluatedRequirement) []string {
	controls := tagStrings(req.Tags, "nist")
	if len(controls) == 0 {
		return []string{"unmapped"}
	}
	seen := map[string]bool{}
	var families []string
	for _, c := range controls {
		fam := c
		if idx := strings.IndexAny(c, "-("); idx > 0 {
			fam = c[:idx]
		}
		fam = strings.ToUpper(strings.TrimSpace(fam))
		if fam != "" && !seen[fam] {
			seen[fam] = true
			families = append(families, fam)
		}
	}
	if len(families) == 0 {
		return []string{"unmapped"}
	}
	return families
}

// tagStrings extracts a tag's values as a string slice, tolerating the string /
// []string / []any shapes HDF tags take.
func tagStrings(tags map[string]any, key string) []string {
	if tags == nil {
		return nil
	}
	switch v := tags[key].(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// resolveThreshold turns the {path|inline} threshold union into a parsed engine
// config. YAML parsing covers JSON too (JSON is a subset), so a .json or .yaml
// path and an inline object all funnel through one decoder.
func resolveThreshold(t *thresholdInput) (*hdfengine.ThresholdConfig, *mcperr.Error) {
	if t == nil {
		return nil, nil
	}
	if t.Path != "" && len(t.Inline) > 0 {
		return nil, mcperr.Arg("threshold sets both path and inline",
			"pass exactly one of threshold.path or threshold.inline")
	}

	var raw []byte
	switch {
	case t.Path != "":
		confined, err := hdfutil.SafePath(mcpRoot(), t.Path)
		if err != nil {
			return nil, mcperr.New(mcperr.PathDenied, "threshold path resolves outside HDF_MCP_ROOT", map[string]any{"path": t.Path})
		}
		b, rerr := os.ReadFile(confined) //nolint:gosec // confined to HDF_MCP_ROOT by SafePath
		if rerr != nil {
			if errors.Is(rerr, os.ErrNotExist) {
				return nil, mcperr.New(mcperr.DocumentNotFound, "no threshold file at the given path", map[string]any{"path": t.Path})
			}
			return nil, redactFileErr(mcperr.DocumentNotFound, "could not read the threshold file", t.Path, rerr)
		}
		raw = b
	case len(t.Inline) > 0:
		b, err := json.Marshal(t.Inline)
		if err != nil {
			return nil, mcperr.New(mcperr.SchemaInvalid, "inline threshold is not serializable", nil).
				WithNextCall("provide a valid threshold spec (compliance/passed/failed bounds)")
		}
		raw = b
	default:
		return nil, nil
	}

	var cfg hdfengine.ThresholdConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, mcperr.New(mcperr.SchemaInvalid, "threshold spec did not parse", map[string]any{"error": err.Error()}).
			WithNextCall("provide a valid threshold spec (compliance/passed/failed bounds), inline or by path")
	}
	return &cfg, nil
}

// boundComplianceResponse enforces the 2k cap: the grouped rollup and the
// threshold failures are the only unbounded collections, so it trims groups (then
// failures) to the largest prefix that fits and names the remedy.
func boundComplianceResponse(out *complianceOutput) {
	if respond.EstimateTokens(mustJSON(out)) <= respond.ConciseTokenBudget {
		return
	}
	// A generous fixed placeholder so the fits() check reserves room for the real
	// (variable-length) truncation notice set afterwards. One notice fits in 320
	// chars; the two notices are budgeted JOINTLY below (the threshold branch
	// reserves the groups notice already set plus this headroom) so a response
	// that trips both branches cannot overflow by their concatenation.
	noticeHeadroom := strings.Repeat("x", 320)
	if len(out.Groups) > 0 {
		kept := largestPrefixFitting(len(out.Groups), func(n int) bool {
			trial := *out
			trial.Groups = out.Groups[:n]
			trial.Truncated = true
			trial.Notice = noticeHeadroom
			return respond.EstimateTokens(mustJSON(&trial)) <= respond.ConciseTokenBudget
		})
		total := len(out.Groups)
		out.Groups = out.Groups[:kept]
		out.Truncated = true
		out.Notice = fmt.Sprintf(
			"Response truncated to stay within the %d-token cap: showing %d of %d %s groups. Request a specific groupBy, or omit groupBy for the ungrouped rollup.",
			respond.ConciseTokenBudget, kept, total, out.GroupBy)
		if respond.EstimateTokens(mustJSON(out)) <= respond.ConciseTokenBudget {
			return
		}
	}
	if out.ThresholdVerdict != nil && len(out.ThresholdVerdict.Failures) > 0 {
		total := len(out.ThresholdVerdict.Failures)
		kept := largestPrefixFitting(total, func(n int) bool {
			trial := *out
			tv := *out.ThresholdVerdict
			tv.Failures = out.ThresholdVerdict.Failures[:n]
			trial.ThresholdVerdict = &tv
			trial.Truncated = true
			// Reserve room for the groups notice already set (empty when the groups
			// branch did not fire) PLUS this branch's notice — the final notice is
			// their concatenation, so budgeting only one headroom underestimates it.
			trial.Notice = strings.TrimSpace(out.Notice + " " + noticeHeadroom)
			return respond.EstimateTokens(mustJSON(&trial)) <= respond.ConciseTokenBudget
		})
		out.ThresholdVerdict.Failures = out.ThresholdVerdict.Failures[:kept]
		out.Truncated = true
		out.Notice = strings.TrimSpace(out.Notice + fmt.Sprintf(
			" Showing %d of %d threshold failures (capped by the %d-token budget; the total count is authoritative). There is no paging for the failure list — fix the reported violations and re-run to surface the rest.",
			kept, total, respond.ConciseTokenBudget))
	}
}

// largestPrefixFitting binary-searches the largest n in [0,max] for which fits(n)
// holds (fits is monotonic in n).
func largestPrefixFitting(count int, fits func(n int) bool) int {
	lo, hi, best := 0, count, 0
	for lo <= hi {
		mid := (lo + hi) / 2
		if fits(mid) {
			best = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return best
}
