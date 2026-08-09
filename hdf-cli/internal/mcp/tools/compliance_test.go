package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func sevPtr(s hdf.Severity) *hdf.Severity { return &s }

func callCompliance(t *testing.T, in complianceInput) (*sdkmcp.CallToolResult, complianceOutput) {
	t.Helper()
	res, out, err := hdfCompliance(loader.New(0, 0, 0))(context.Background(), nil, in)
	if err != nil {
		t.Fatalf("hdfCompliance Go error (should be taxonomy tool result): %v", err)
	}
	return res, out
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

func TestHdfCompliance_ComplianceAndCounts(t *testing.T) {
	path := writeRoot(t, "c.json", readToolsFixture(t, "compliance-results.json"))
	_, out := callCompliance(t, complianceInput{Source: handle.Source{Path: path}})
	// Raw compliance: passed {C,E}=2 / relevant {A,B,C,D,E}=5 = 40%.
	if out.Compliance != 40.0 {
		t.Errorf("compliance = %v, want 40", out.Compliance)
	}
	counts, ok := out.Counts.(*hdfengine.StatusCounts)
	if !ok || counts.Passed.Total != 2 || counts.Failed.Total != 3 {
		t.Errorf("counts passed/failed = %+v, want passed.total=2 failed.total=3", out.Counts)
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
	// RHEL9-STIG {A fail, B fail, C pass} = 1/3 = 33.33; K8S {D fail, E pass} = 1/2 = 50.
	if rhel.Compliance != 33.33 {
		t.Errorf("RHEL9-STIG compliance = %v, want 33.33", rhel.Compliance)
	}
	if k8s.Compliance != 50.0 {
		t.Errorf("K8S-NODE-STIG compliance = %v, want 50", k8s.Compliance)
	}
}

func TestHdfCompliance_GroupBySeverity(t *testing.T) {
	path := writeRoot(t, "c.json", readToolsFixture(t, "compliance-results.json"))
	_, out := callCompliance(t, complianceInput{Source: handle.Source{Path: path}, GroupBy: "severity"})
	want := map[string]float64{"critical": 0.0, "medium": 0.0, "high": 100.0, "informational": 100.0}
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
	// AC{A fail}=0, CM{B fail}=0, IA{C pass}=100, AU{D fail}=0, SC{E pass}=100.
	want := map[string]float64{"AC": 0.0, "CM": 0.0, "IA": 100.0, "AU": 0.0, "SC": 100.0}
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
	if res == nil || !res.IsError {
		t.Fatal("threshold with both path and inline must error")
	}
	if tr := toolResultPayload(t, res); tr.Code != mcperr.AmbiguousFormat {
		t.Errorf("code = %q, want AMBIGUOUS_FORMAT", tr.Code)
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
	if out.Compliance != 40.0 || out.DocType != "results" {
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
	if res == nil || !res.IsError {
		t.Fatal("an unknown groupBy must error")
	}
	if tr := toolResultPayload(t, res); tr.Code != mcperr.AmbiguousFormat {
		t.Errorf("code = %q, want AMBIGUOUS_FORMAT", tr.Code)
	}
}

func TestGroupSeverity_ExplicitAndDerived(t *testing.T) {
	if g := groupSeverity(hdf.EvaluatedRequirement{Severity: sevPtr(hdf.SeverityLow), Impact: 0.95}); g != "low" {
		t.Errorf("explicit severity wins, got %q want low", g)
	}
	if g := groupSeverity(hdf.EvaluatedRequirement{Impact: 0.95}); g != "critical" {
		t.Errorf("impact-derived, got %q want critical", g)
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
		DocType: "results", Counts: &hdfengine.StatusCounts{},
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
	out := complianceOutput{DocType: "results", GroupBy: "nistFamily", Counts: &hdfengine.StatusCounts{}}
	for i := 0; i < 400; i++ {
		out.Groups = append(out.Groups, groupRollup{
			Group:      "FAM-" + strings.Repeat("x", 3) + string(rune('A'+i%26)) + strings.Repeat("y", 2),
			Compliance: 50.0,
			Counts:     &hdfengine.StatusCounts{},
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
