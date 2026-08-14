package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// driveToolCall drives a real initialize + tools/call round-trip through the SDK
// session so SDK output-schema validation runs — unlike callCompliance, which
// invokes the handler directly and never exercises the wire-level validation.
// Returns the full JSON-RPC response message for id 2 (result or error).
func driveToolCall(t *testing.T, s *sdkmcp.Server, name string, args map[string]any) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5e9)
	defer cancel()
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go func() { _ = s.Run(ctx, &sdkmcp.IOTransport{Reader: reqR, Writer: respW}); _ = respW.Close() }()
	call, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	})
	go func() {
		_, _ = reqW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}` + "\n" +
			`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
			string(call) + "\n"))
	}()
	dec := json.NewDecoder(respR)
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("no tools/call response: %v", err)
		}
		if m["id"] == float64(2) {
			_ = reqW.Close()
			cancel()
			return m
		}
	}
}

// TestHdfCompliance_ErrorReturnSurfacesToolErrorThroughSDK is the lj0g.10
// regression guard. An error-path tools/call must surface its taxonomy toolError
// through the real SDK session; the pre-fix handler returned a zero-value
// complianceOutput{} whose nil counts map failed output-schema validation, so the
// SDK replaced the WRONG_DOC_TYPE toolError with a confusing "validating tool
// output: ... counts ... null" JSON-RPC error. Fails on pre-fix code.
func TestHdfCompliance_ErrorReturnSurfacesToolErrorThroughSDK(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	if err := os.WriteFile(filepath.Join(root, "system.json"), readCLIFixture(t, "system.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "1"}, nil)
	RegisterAll(s)

	m := driveToolCall(t, s, "hdf_compliance", map[string]any{"source": map[string]any{"path": "system.json"}})

	if e, ok := m["error"]; ok {
		t.Fatalf("error-path tools/call was masked by an SDK output-validation error instead of surfacing the toolError: %v", e)
	}
	res, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in tools/call response: %v", m)
	}
	if isErr, _ := res["isError"].(bool); !isErr {
		t.Fatalf("expected an isError toolResult, got %v", res)
	}
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		t.Fatal("toolResult carried no content")
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, string(mcperr.WrongDocType)) {
		t.Errorf("toolError should name %s, got %q", mcperr.WrongDocType, text)
	}
}

func sevPtr(s hdf.Severity) *hdf.Severity { return &s }

func callCompliance(t *testing.T, in complianceInput) (*sdkmcp.CallToolResult, complianceOutput) {
	t.Helper()
	res, out, err := hdfCompliance(loader.New(0, 0, 0))(context.Background(), nil, in)
	if err != nil {
		t.Fatalf("hdfCompliance Go error (should be taxonomy tool result): %v", err)
	}
	return res, out
}

// countTotal reads counts.<status>.total from the value-typed counts output.
func countTotal(counts map[string]map[string]int, status string) int {
	if s, ok := counts[status]; ok {
		return s["total"]
	}
	return -1
}

func findGroup(groups []groupRollup, name string) *groupRollup {
	for i := range groups {
		if groups[i].Group == name {
			return &groups[i]
		}
	}
	return nil
}

// The card's designated first-failing test: a results file carrying an
// agent-attributed override reports agentOverrides.count and a complianceDelta
// reflecting how much those overrides moved compliance (§3 detective surface).
func TestHdfCompliance_AgentOverrideCount(t *testing.T) {
	path := writeRoot(t, "c.json", readToolsFixture(t, "compliance-results.json"))
	res, out := callCompliance(t, complianceInput{Source: handle.Source{Path: path}})
	if res != nil {
		t.Fatalf("valid results must not error: %s", payloadText(t, res))
	}
	if out.AgentOverrides.Count != 1 {
		t.Errorf("agentOverrides.count = %d, want 1 (only the agent override; the system one is excluded)", out.AgentOverrides.Count)
	}
	// Effective compliance with the agent override (75%) minus without it (50%) = 25.
	if out.AgentOverrides.ComplianceDelta != 25.0 {
		t.Errorf("agentOverrides.complianceDelta = %v, want 25", out.AgentOverrides.ComplianceDelta)
	}
}

// TestComplianceCountsImpactZeroAsNoImpact is the lj0g.4 first-failing test: an
// impact-0 requirement (InSpec skip: result status notReviewed, explicit STIG
// severity) is Not Applicable by HDF's canonical rule and must land in no_impact,
// not skipped — and must be excluded from the compliance denominator.
func TestComplianceCountsImpactZeroAsNoImpact(t *testing.T) {
	path := writeRoot(t, "iz.json", readToolsFixture(t, "impact-zero.json"))
	_, out := callCompliance(t, complianceInput{Source: handle.Source{Path: path}})
	// 3 impact-0 (severity medium, notReviewed) → notApplicable/no_impact.
	if got := countTotal(out.Counts, "no_impact"); got != 3 {
		t.Errorf("no_impact.total = %d, want 3 (the impact-0 requirements)", got)
	}
	// 1 impact-0.5 notReviewed → genuinely skipped.
	if got := countTotal(out.Counts, "skipped"); got != 1 {
		t.Errorf("skipped.total = %d, want 1 (only the impact>0 notReviewed control)", got)
	}
	// compliance = passed / (passed+failed+skipped+error) = 1/(1+0+1+0) = 50; the
	// 3 Not Applicable are excluded from the denominator (raw counting gave 20).
	if out.Compliance != 50.0 {
		t.Errorf("compliance = %v, want 50 (Not Applicable excluded from denominator)", out.Compliance)
	}
}

// TestSeverityAgreesAcrossQueryAndCompliance is lj0g.5's first-failing test: one
// requirement must have one severity. The canonical rule is explicit STIG tag
// first, impact-derived fallback (deriveSeverity) — shared by hdf_query rows and
// hdf_compliance counts. Covers all four combinations of {impact 0, impact>0} ×
// {explicit tag, no tag}.
func TestSeverityAgreesAcrossQueryAndCompliance(t *testing.T) {
	path := writeRoot(t, "sm.json", readToolsFixture(t, "severity-mix.json"))

	// hdf_query row severity per requirement.
	_, q := callQuery(t, queryInput{Source: handle.Source{Path: path}})
	qSev := map[string]string{}
	for _, r := range q.Requirements {
		qSev[r["id"].(string)] = r["severity"].(string)
	}
	want := map[string]string{
		"S-0-TAG-HIGH":  "high",   // impact 0 + explicit high → high (not informational/none)
		"S-0-NOTAG":     "none",   // impact 0 + no tag → none
		"S-P-TAG-LOW":   "low",    // impact 0.7 + explicit low → low (explicit beats impact-derived high)
		"S-P-NOTAG-MED": "medium", // impact 0.5 + no tag → medium
	}
	for id, sev := range want {
		if qSev[id] != sev {
			t.Errorf("hdf_query severity[%s] = %q, want %q", id, qSev[id], sev)
		}
	}

	// hdf_compliance counts must place each requirement in the matching severity
	// bucket of its status: notApplicable (no_impact) high+none; failed low+medium.
	_, c := callCompliance(t, complianceInput{Source: handle.Source{Path: path}})
	na := c.Counts["no_impact"]
	failed := c.Counts["failed"]
	checkBucket := func(bucket map[string]int, sev string) {
		if bucket[sev] != 1 {
			t.Errorf("compliance bucket missing severity %q=1; got %v", sev, bucket)
		}
	}
	checkBucket(na, "high")       // S-0-TAG-HIGH → notApplicable/high
	checkBucket(na, "none")       // S-0-NOTAG → notApplicable/none
	checkBucket(failed, "low")    // S-P-TAG-LOW → failed/low
	checkBucket(failed, "medium") // S-P-NOTAG-MED → failed/medium
}

// TestCountsOutputSchemaIsTyped is lj0g.3's first-failing test: the counts output
// schema (both the top-level and per-group occurrences) declares its value shape
// as object→object→integer, not a bare additionalProperties:true. Full named-key
// typing measured ~2x the per-tool ceiling, so the status/severity keys stay
// undeclared by decision (documented in the tool description + ADR); the value
// types are declared.
func TestCountsOutputSchemaIsTyped(t *testing.T) {
	s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "v"}, nil)
	RegisterCompliance(s, loader.New(0, 0, 0))
	var r struct {
		Tools []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal([]byte(driveToolsListJSON(t, s)), &r); err != nil {
		t.Fatal(err)
	}
	var tool map[string]any
	for _, tl := range r.Tools {
		if tl["name"] == "hdf_compliance" {
			tool = tl
		}
	}
	if tool == nil {
		t.Fatal("hdf_compliance not listed")
	}
	// integerValued reports whether a counts schema is object→object→integer.
	integerValued := func(counts any) bool {
		m, ok := counts.(map[string]any)
		if !ok {
			return false
		}
		ap, ok := m["additionalProperties"].(map[string]any) // severity level
		if !ok {
			return false
		}
		leaf, ok := ap["additionalProperties"].(map[string]any) // int level
		return ok && leaf["type"] == "integer"
	}
	out := tool["outputSchema"].(map[string]any)["properties"].(map[string]any)
	if !integerValued(out["counts"]) {
		t.Errorf("top-level counts must be value-typed object→object→integer, got %v", out["counts"])
	}
	groupCounts := out["groups"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["counts"]
	if !integerValued(groupCounts) {
		t.Errorf("per-group counts must be value-typed object→object→integer, got %v", groupCounts)
	}
}

// TestComplianceDescriptionStatesStatusConvention is lj0g.2's first-failing test:
// the registered description must name the status convention the counts use
// (effective status) and cross-reference hdf_query as the per-requirement status
// surface, so a tool-selecting agent isn't misled into using counts for a
// per-requirement question.
func TestComplianceDescriptionStatesStatusConvention(t *testing.T) {
	s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "v"}, nil)
	RegisterCompliance(s, loader.New(0, 0, 0))
	raw := driveToolsListJSON(t, s)
	for _, frag := range []string{"effective status", "per-requirement", "hdf_query"} {
		if !strings.Contains(raw, frag) {
			t.Errorf("hdf_compliance description must state %q (status convention + hdf_query cross-reference)", frag)
		}
	}
	// Must not resurrect the misleading "raw result statuses" claim.
	if strings.Contains(raw, "raw result statuses") {
		t.Error("description must not claim 'raw result statuses' — counts are effective")
	}
}

// TestComplianceCountsVocabularyIsDocumented is lj0g.7's first-failing test: the
// counts payload uses SAF vocabulary (skipped/no_impact) and the tool description
// states the SAF↔schema mapping, so the two surfaces express one contract and
// cannot drift. No schema-vocab keys leak into counts; no third vocabulary.
func TestComplianceCountsVocabularyIsDocumented(t *testing.T) {
	path := writeRoot(t, "iz.json", readToolsFixture(t, "impact-zero.json"))
	_, out := callCompliance(t, complianceInput{Source: handle.Source{Path: path}})
	for _, saf := range []string{"passed", "failed", "skipped", "error", "no_impact"} {
		if _, ok := out.Counts[saf]; !ok {
			t.Errorf("counts must use SAF key %q", saf)
		}
	}
	for _, schema := range []string{"notReviewed", "notApplicable"} {
		if _, ok := out.Counts[schema]; ok {
			t.Errorf("counts must NOT carry schema key %q — counts is SAF-vocabulary only", schema)
		}
	}
	// The description must state the mapping (the reachable place an agent reads).
	s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "v"}, nil)
	RegisterCompliance(s, loader.New(0, 0, 0))
	raw := driveToolsListJSON(t, s)
	for _, frag := range []string{"skipped = notReviewed", "no_impact = notApplicable"} {
		if !strings.Contains(raw, frag) {
			t.Errorf("hdf_compliance description must document the vocabulary mapping %q", frag)
		}
	}
}

func TestHdfCompliance_ComplianceAndCounts(t *testing.T) {
	path := writeRoot(t, "c.json", readToolsFixture(t, "compliance-results.json"))
	_, out := callCompliance(t, complianceInput{Source: handle.Source{Path: path}})
	// Effective compliance: A,B passed (overrides), C passed, D failed, E impact-0
	// → notApplicable (excluded). passed 3 / relevant {A,B,C,D}=4 = 75%.
	if out.Compliance != 75.0 {
		t.Errorf("compliance = %v, want 75", out.Compliance)
	}
	if countTotal(out.Counts, "passed") != 3 || countTotal(out.Counts, "failed") != 1 {
		t.Errorf("counts passed/failed = %+v, want passed.total=3 failed.total=1", out.Counts)
	}
	if countTotal(out.Counts, "no_impact") != 1 {
		t.Errorf("no_impact.total = %d, want 1 (the impact-0 requirement)", countTotal(out.Counts, "no_impact"))
	}
	if out.DocType != "results" || out.Handle == "" {
		t.Errorf("envelope must carry docType+handle, got docType=%q handle=%q", out.DocType, out.Handle)
	}
	// No groupBy → ungrouped.
	if out.GroupBy != "" || out.Groups != nil {
		t.Errorf("unset groupBy must return the ungrouped rollup, got groupBy=%q groups=%v", out.GroupBy, out.Groups)
	}
}

func TestHdfCompliance_GroupByBaseline(t *testing.T) {
	path := writeRoot(t, "c.json", readToolsFixture(t, "compliance-results.json"))
	_, out := callCompliance(t, complianceInput{Source: handle.Source{Path: path}, GroupBy: "baseline"})
	if out.GroupBy != "baseline" || len(out.Groups) != 2 {
		t.Fatalf("expected 2 baseline groups, got groupBy=%q groups=%d", out.GroupBy, len(out.Groups))
	}
	rhel := findGroup(out.Groups, "RHEL9-STIG")
	k8s := findGroup(out.Groups, "K8S-NODE-STIG")
	if rhel == nil || k8s == nil {
		t.Fatalf("missing expected baseline groups: %+v", out.Groups)
	}
	// Effective: RHEL9-STIG {A,B,C all pass (overrides)} = 3/3 = 100; K8S {D fail,
	// E impact-0 → notApplicable, excluded} = 0/1 = 0.
	if rhel.Compliance != 100.0 {
		t.Errorf("RHEL9-STIG compliance = %v, want 100", rhel.Compliance)
	}
	if k8s.Compliance != 0.0 {
		t.Errorf("K8S-NODE-STIG compliance = %v, want 0", k8s.Compliance)
	}
}

func TestHdfCompliance_GroupBySeverity(t *testing.T) {
	path := writeRoot(t, "c.json", readToolsFixture(t, "compliance-results.json"))
	_, out := callCompliance(t, complianceInput{Source: handle.Source{Path: path}, GroupBy: "severity"})
	// Effective: A crit passed→100; B med passed + D med failed→50; C high passed→100;
	// E impact-0 no tag → severity "none", notApplicable (relevant 0 → 0%).
	want := map[string]float64{"critical": 100.0, "medium": 50.0, "high": 100.0, "none": 0.0}
	for sev, wantPct := range want {
		g := findGroup(out.Groups, sev)
		if g == nil {
			t.Errorf("missing severity group %q; got %v", sev, out.Groups)
			continue
		}
		if g.Compliance != wantPct {
			t.Errorf("severity %q compliance = %v, want %v", sev, g.Compliance, wantPct)
		}
	}
}

func TestHdfCompliance_GroupByNistFamily(t *testing.T) {
	path := writeRoot(t, "c.json", readToolsFixture(t, "compliance-results.json"))
	_, out := callCompliance(t, complianceInput{Source: handle.Source{Path: path}, GroupBy: "nistFamily"})
	// Effective: AC{A passed}=100, CM{B passed}=100, IA{C passed}=100, AU{D failed}=0,
	// SC{E impact-0 → notApplicable, relevant 0}=0.
	want := map[string]float64{"AC": 100.0, "CM": 100.0, "IA": 100.0, "AU": 0.0, "SC": 0.0}
	if len(out.Groups) != len(want) {
		t.Errorf("expected %d nistFamily groups, got %d (%v)", len(want), len(out.Groups), out.Groups)
	}
	for fam, wantPct := range want {
		g := findGroup(out.Groups, fam)
		if g == nil || g.Compliance != wantPct {
			t.Errorf("nistFamily %q = %v, want %v", fam, g, wantPct)
		}
	}
}

func TestHdfCompliance_ThresholdInline(t *testing.T) {
	path := writeRoot(t, "c.json", readToolsFixture(t, "compliance-results.json"))

	// compliance.min 80 > actual 40 → fail with a populated failures list.
	_, fail := callCompliance(t, complianceInput{
		Source:    handle.Source{Path: path},
		Threshold: &thresholdInput{Inline: map[string]any{"compliance": map[string]any{"min": 80}}},
	})
	if fail.ThresholdVerdict == nil || fail.ThresholdVerdict.Pass || len(fail.ThresholdVerdict.Failures) == 0 {
		t.Errorf("compliance.min=80 must fail with failures, got %+v", fail.ThresholdVerdict)
	}

	// compliance.min 20 < actual 40 → pass, no failures.
	_, pass := callCompliance(t, complianceInput{
		Source:    handle.Source{Path: path},
		Threshold: &thresholdInput{Inline: map[string]any{"compliance": map[string]any{"min": 20}}},
	})
	if pass.ThresholdVerdict == nil || !pass.ThresholdVerdict.Pass || len(pass.ThresholdVerdict.Failures) != 0 {
		t.Errorf("compliance.min=20 must pass with no failures, got %+v", pass.ThresholdVerdict)
	}
}

func TestHdfCompliance_ThresholdFromPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	if err := os.WriteFile(filepath.Join(root, "scan.json"), readToolsFixture(t, "compliance-results.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// YAML threshold file (yaml.Unmarshal also accepts JSON).
	if err := os.WriteFile(filepath.Join(root, "threshold.yaml"), []byte("compliance:\n  min: 90\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out := callCompliance(t, complianceInput{
		Source:    handle.Source{Path: "scan.json"},
		Threshold: &thresholdInput{Path: "threshold.yaml"},
	})
	if out.ThresholdVerdict == nil || out.ThresholdVerdict.Pass {
		t.Errorf("compliance.min=90 from a path must fail, got %+v", out.ThresholdVerdict)
	}
}

func TestHdfCompliance_ThresholdAmbiguous(t *testing.T) {
	path := writeRoot(t, "c.json", readToolsFixture(t, "compliance-results.json"))
	res, _ := callCompliance(t, complianceInput{
		Source:    handle.Source{Path: path},
		Threshold: &thresholdInput{Path: "t.yaml", Inline: map[string]any{"compliance": map[string]any{"min": 80}}},
	})
	assertArgError(t, res, "threshold sets both path and inline")
}

// TestHdfCompliance_PerControlThresholdUsesEffectiveStatus is the lj0g.11
// regression guard: a per-control controls: list is validated against EFFECTIVE
// status, matching the aggregate counts and the CLI threshold path. An impact-0
// notReviewed control listed under no_impact must satisfy the check (effective
// notApplicable → no_impact), not fail as skipped. Fails on pre-fix code, which
// passed the raw MapControlIDs to ValidateThresholds while counting effectively.
func TestHdfCompliance_PerControlThresholdUsesEffectiveStatus(t *testing.T) {
	path := writeRoot(t, "iz.json", readToolsFixture(t, "impact-zero.json"))
	_, out := callCompliance(t, complianceInput{
		Source: handle.Source{Path: path},
		Threshold: &thresholdInput{Inline: map[string]any{
			"no_impact": map[string]any{"medium": map[string]any{"controls": []any{"V-NA-1"}}},
		}},
	})
	if out.ThresholdVerdict == nil {
		t.Fatal("expected a threshold verdict")
	}
	if !out.ThresholdVerdict.Pass {
		t.Errorf("V-NA-1 (impact 0, medium, notReviewed) must satisfy no_impact.medium.controls under effective status; got failures %v", out.ThresholdVerdict.Failures)
	}
}

// TestThresholdTruncationNoticeIsActionable is the lj0g.12 regression guard.
// When the thresholdVerdict.failures list overflows the token-budget cap, the
// notice must report the true total, must NOT advise making the threshold
// "smaller" (a threshold is a set of bounds, not a page size), and must name the
// real mechanism for the withheld failures (fix + re-run) — matching the house
// style lj0g.6 set for hdf_query. Many non-existent control IDs generate one
// "not found" violation each, overflowing the cap without a huge fixture.
func TestThresholdTruncationNoticeIsActionable(t *testing.T) {
	path := writeRoot(t, "c.json", readToolsFixture(t, "compliance-results.json"))
	const wantTotal = 400
	fakes := make([]any, 0, wantTotal)
	for i := 0; i < wantTotal; i++ {
		fakes = append(fakes, fmt.Sprintf("MISSING-%03d", i))
	}
	_, out := callCompliance(t, complianceInput{
		Source: handle.Source{Path: path},
		Threshold: &thresholdInput{Inline: map[string]any{
			"passed": map[string]any{"total": map[string]any{"controls": fakes}},
		}},
	})
	if out.ThresholdVerdict == nil || out.ThresholdVerdict.Pass {
		t.Fatal("expected a failing threshold verdict")
	}
	if !out.Truncated {
		t.Fatalf("expected truncation with %d failures; failures kept=%d notice=%q", wantTotal, len(out.ThresholdVerdict.Failures), out.Notice)
	}
	n := out.Notice
	if strings.Contains(strings.ToLower(n), "smaller threshold") {
		t.Errorf("notice must not advise a 'smaller threshold': %q", n)
	}
	if !strings.Contains(n, fmt.Sprintf("of %d", wantTotal)) {
		t.Errorf("notice must report the true total (%d): %q", wantTotal, n)
	}
	if !strings.Contains(n, "re-run") || !strings.Contains(strings.ToLower(n), "fix") {
		t.Errorf("notice must name the real mechanism (fix the reported violations and re-run): %q", n)
	}
}

func TestHdfCompliance_WrongDocType(t *testing.T) {
	path := writeRoot(t, "system.json", readCLIFixture(t, "system.json"))
	res, _ := callCompliance(t, complianceInput{Source: handle.Source{Path: path}})
	if res == nil || !res.IsError {
		t.Fatal("a system document must be rejected")
	}
	tr := toolResultPayload(t, res)
	if tr.Code != mcperr.WrongDocType || !strings.Contains(tr.NextCall, "hdf_inspect") {
		t.Errorf("want WRONG_DOC_TYPE naming hdf_inspect, got code=%q next=%q", tr.Code, tr.NextCall)
	}
}

func TestHdfCompliance_SchemaInvalid(t *testing.T) {
	bad := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"x","descriptions":[],"impact":5,"tags":{},"results":[]}]}],"statistics":{"duration":1}}`)
	path := writeRoot(t, "bad.json", bad)
	res, _ := callCompliance(t, complianceInput{Source: handle.Source{Path: path}})
	if res == nil || !res.IsError {
		t.Fatal("a schema-invalid results doc must error")
	}
	if tr := toolResultPayload(t, res); tr.Code != mcperr.SchemaInvalid {
		t.Errorf("code = %q, want SCHEMA_INVALID", tr.Code)
	}
}

func TestHdfCompliance_HandleSource(t *testing.T) {
	// A handle minted by hdf_open resolves the same document (§8 source union).
	path := writeRoot(t, "c.json", readToolsFixture(t, "compliance-results.json"))
	_, opened := callOpen(t, openInput{Source: handle.Source{Path: path}})
	if opened.Handle == "" {
		t.Fatal("open must mint a handle")
	}
	_, out := callCompliance(t, complianceInput{Source: handle.Source{Handle: opened.Handle}})
	if out.Compliance != 75.0 || out.DocType != "results" {
		t.Errorf("handle source must resolve the same results, got compliance=%v docType=%q", out.Compliance, out.DocType)
	}
}

func TestHdfCompliance_Annotations(t *testing.T) {
	s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "v"}, nil)
	RegisterCompliance(s, loader.New(0, 0, 0))
	raw := driveToolsListJSON(t, s)
	if !strings.Contains(raw, `"name":"hdf_compliance"`) {
		t.Fatalf("hdf_compliance not listed: %s", raw)
	}
	if !strings.Contains(raw, `"readOnlyHint":true`) || !strings.Contains(raw, `"openWorldHint":false`) {
		t.Errorf("hdf_compliance must be read-only + closed-world: %s", raw)
	}
}

func TestHdfCompliance_UnknownGroupBy(t *testing.T) {
	path := writeRoot(t, "c.json", readToolsFixture(t, "compliance-results.json"))
	res, _ := callCompliance(t, complianceInput{Source: handle.Source{Path: path}, GroupBy: "bogus"})
	assertArgError(t, res, "unknown groupBy")
}

func TestGroupSeverity_ExplicitAndDerived(t *testing.T) {
	if g := groupSeverity(hdf.EvaluatedRequirement{Severity: sevPtr(hdf.SeverityLow), Impact: 0.95}); g != "low" {
		t.Errorf("explicit severity wins, got %q want low", g)
	}
	if g := groupSeverity(hdf.EvaluatedRequirement{Impact: 0.95}); g != "critical" {
		t.Errorf("impact-derived, got %q want critical", g)
	}
	// Zero band: no explicit tag → "none" (matches DeriveSeverity / the counts),
	// NOT "informational" — the surviving-fork regression from lj0g.5 review.
	if g := groupSeverity(hdf.EvaluatedRequirement{Impact: 0.0}); g != "none" {
		t.Errorf("impact-0 no tag group key = %q, want none (must match DeriveSeverity, not raw ImpactToSeverity)", g)
	}
	// Zero band with an explicit tag → the tag wins.
	if g := groupSeverity(hdf.EvaluatedRequirement{Severity: sevPtr(hdf.SeverityMedium), Impact: 0.0}); g != "medium" {
		t.Errorf("impact-0 tagged medium group key = %q, want medium", g)
	}
}

func TestNistFamilies(t *testing.T) {
	cases := []struct {
		name string
		tags map[string]any
		want []string
	}{
		{"multi + sub-control", map[string]any{"nist": []any{"AC-2", "AC-6(1)", "CM-6"}}, []string{"AC", "CM"}},
		{"no nist tag", map[string]any{"cci": []any{"CCI-1"}}, []string{"unmapped"}},
		{"nil tags", nil, []string{"unmapped"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := nistFamilies(hdf.EvaluatedRequirement{Tags: c.tags})
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("families = %v, want %v", got, c.want)
			}
		})
	}
}

func TestTagStrings_Shapes(t *testing.T) {
	if got := tagStrings(map[string]any{"nist": "AC-2"}, "nist"); len(got) != 1 || got[0] != "AC-2" {
		t.Errorf("string shape = %v", got)
	}
	if got := tagStrings(map[string]any{"nist": []string{"AC-2", "CM-6"}}, "nist"); len(got) != 2 {
		t.Errorf("[]string shape = %v", got)
	}
	if got := tagStrings(map[string]any{"nist": []any{"AC-2", 42}}, "nist"); len(got) != 1 {
		t.Errorf("[]any shape must skip non-strings, got %v", got)
	}
	if got := tagStrings(nil, "nist"); got != nil {
		t.Errorf("nil tags = %v, want nil", got)
	}
	if got := tagStrings(map[string]any{"nist": 42}, "nist"); got != nil {
		t.Errorf("non-string tag value = %v, want nil", got)
	}
}

func TestResolveThreshold_Errors(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)

	if _, err := resolveThreshold(nil); err != nil {
		t.Errorf("nil threshold must be a no-op, got %v", err)
	}
	// An empty threshold object (neither path nor inline) is also a no-op.
	if cfg, e := resolveThreshold(&thresholdInput{}); e != nil || cfg != nil {
		t.Errorf("empty threshold must resolve to nil,nil; got cfg=%v err=%v", cfg, e)
	}
	// Path escaping the root → PathDenied.
	if _, e := resolveThreshold(&thresholdInput{Path: "../escape.yaml"}); e == nil || e.Code != mcperr.PathDenied {
		t.Errorf("path escape must be PATH_DENIED, got %v", e)
	}
	// Missing file → DocumentNotFound.
	if _, e := resolveThreshold(&thresholdInput{Path: "nope.yaml"}); e == nil || e.Code != mcperr.DocumentNotFound {
		t.Errorf("missing file must be DOCUMENT_NOT_FOUND, got %v", e)
	}
	// Malformed content → SchemaInvalid.
	if err := os.WriteFile(filepath.Join(root, "bad.yaml"), []byte("compliance: [1,2,3]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, e := resolveThreshold(&thresholdInput{Path: "bad.yaml"}); e == nil || e.Code != mcperr.SchemaInvalid {
		t.Errorf("malformed threshold must be SCHEMA_INVALID, got %v", e)
	}
}

func TestBoundComplianceResponse_TrimsFailures(t *testing.T) {
	out := complianceOutput{
		DocType: "results", Counts: map[string]map[string]int{},
		ThresholdVerdict: &thresholdVerdict{Pass: false},
	}
	for i := 0; i < 500; i++ {
		out.ThresholdVerdict.Failures = append(out.ThresholdVerdict.Failures,
			"failed.critical: control "+strings.Repeat("V-", 4)+string(rune('A'+i%26))+" exceeds maximum 0")
	}
	boundComplianceResponse(&out)
	if !out.Truncated || out.Notice == "" {
		t.Fatal("an over-budget failures list must truncate with a notice")
	}
	if len(out.ThresholdVerdict.Failures) >= 500 {
		t.Errorf("failures must be trimmed, kept %d of 500", len(out.ThresholdVerdict.Failures))
	}
	if respond.EstimateTokens(mustJSON(&out)) > respond.ConciseTokenBudget {
		t.Errorf("bounded response still exceeds the %d-token cap", respond.ConciseTokenBudget)
	}
}

func TestBoundComplianceResponse_TrimsGroups(t *testing.T) {
	out := complianceOutput{DocType: "results", GroupBy: "nistFamily", Counts: map[string]map[string]int{}}
	for i := 0; i < 400; i++ {
		out.Groups = append(out.Groups, groupRollup{
			Group:      "FAM-" + strings.Repeat("x", 3) + string(rune('A'+i%26)) + strings.Repeat("y", 2),
			Compliance: 50.0,
			Counts:     map[string]map[string]int{},
		})
	}
	boundComplianceResponse(&out)
	if !out.Truncated || out.Notice == "" {
		t.Fatal("an over-budget grouped response must truncate with a notice")
	}
	if len(out.Groups) >= 400 {
		t.Errorf("groups must be trimmed, kept %d of 400", len(out.Groups))
	}
	if respond.EstimateTokens(mustJSON(&out)) > respond.ConciseTokenBudget {
		t.Errorf("bounded response still exceeds the %d-token cap", respond.ConciseTokenBudget)
	}
	if !strings.Contains(out.Notice, "groupBy") {
		t.Errorf("notice should name the narrowing parameter, got %q", out.Notice)
	}
}

// When BOTH the groups branch and the threshold branch truncate, the final
// notice is their concatenation. Each branch independently reserving one fixed
// headroom under-budgets that concatenation, pushing a boundary response over the
// cap. The two notices must be budgeted jointly so the compound case still fits.
func TestBoundComplianceResponse_CompoundTruncationFitsBudget(t *testing.T) {
	out := complianceOutput{
		DocType: "results", GroupBy: "nistFamily", Counts: map[string]map[string]int{},
		ThresholdVerdict: &thresholdVerdict{Pass: false},
	}
	for i := 0; i < 400; i++ {
		out.Groups = append(out.Groups, groupRollup{
			Group:      "FAM-" + strings.Repeat("x", 3) + string(rune('A'+i%26)) + strings.Repeat("y", 2),
			Compliance: 50.0,
			Counts:     map[string]map[string]int{},
		})
	}
	for i := 0; i < 500; i++ {
		out.ThresholdVerdict.Failures = append(out.ThresholdVerdict.Failures,
			"failed.critical: control "+strings.Repeat("V-", 4)+string(rune('A'+i%26))+" exceeds maximum 0")
	}
	boundComplianceResponse(&out)
	// Both collections must have truncated (this is the compound case).
	if len(out.Groups) >= 400 || len(out.ThresholdVerdict.Failures) >= 500 {
		t.Fatalf("both collections must truncate: %d groups, %d failures", len(out.Groups), len(out.ThresholdVerdict.Failures))
	}
	// The concatenated notice must NOT push the response over the cap.
	if got := respond.EstimateTokens(mustJSON(&out)); got > respond.ConciseTokenBudget {
		t.Errorf("compound-truncation response is %d tokens, over the %d cap", got, respond.ConciseTokenBudget)
	}
	// The combined notice carries both remedies.
	if !strings.Contains(out.Notice, "groupBy") || !strings.Contains(out.Notice, "threshold failures") {
		t.Errorf("compound notice must carry both remedies, got %q", out.Notice)
	}
}
