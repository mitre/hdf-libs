package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// A results doc with one failing requirement, and an amendment that waives it to
// passed — applying flips compliance 0% → 100% and changes exactly 1 requirement.
const applyResultsDoc = `{
  "baselines": [{
    "name": "test-baseline",
    "requirements": [{
      "id": "AC-1",
      "impact": 0.5,
      "title": "Access Control Policy",
      "descriptions": [{"label": "default", "data": "test"}],
      "results": [{"status": "failed", "codeDesc": "test", "startTime": "2026-01-01T00:00:00Z"}],
      "tags": {}
    }]
  }],
  "statistics": {"duration": 0.1}
}`

const applyAmendmentsDoc = `{
  "name": "Q1 Waivers",
  "overrides": [{
    "type": "waiver",
    "requirementId": "AC-1",
    "status": "passed",
    "reason": "Risk accepted per ATO",
    "appliedBy": {"type": "email", "identifier": "admin@example.com"},
    "appliedAt": "2026-03-01T00:00:00Z",
    "expiresAt": "2099-12-31T00:00:00Z"
  }]
}`

// applyEnv writes the results + amendments docs into a fresh HDF_MCP_ROOT and
// returns the root plus their relative paths.
func applyEnv(t *testing.T) (root, resultsRel, amendRel string) {
	t.Helper()
	root = t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	resultsRel, amendRel = "results.json", "amendments.json"
	if err := os.WriteFile(filepath.Join(root, resultsRel), []byte(applyResultsDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, amendRel), []byte(applyAmendmentsDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, resultsRel, amendRel
}

func callApply(t *testing.T, in applyAmendmentInput) (*sdkmcp.CallToolResult, applyAmendmentOutput) {
	t.Helper()
	res, out, err := hdfApplyAmendment(loader.New(0, 0, 0))(context.Background(), nil, in)
	if err != nil {
		t.Fatalf("hdfApplyAmendment returned a Go error (should use taxonomy paths): %v", err)
	}
	return res, out
}

func applyInput(results, amend, output string, dry bool) applyAmendmentInput {
	return applyAmendmentInput{
		Results:    handle.Source{Path: results},
		Amendments: handle.Source{Path: amend},
		Output:     output,
		DryRun:     dry,
	}
}

// TestApplyAmendment_NeverOverwritesInput is the card's designated first-failing
// test: in every mode the results input file is byte-unchanged and any output
// lands at a distinct path.
func TestApplyAmendment_NeverOverwritesInput(t *testing.T) {
	modes := []struct {
		name    string
		writes  string
		dry     bool
		writeOK bool // an output file is expected
	}{
		{"default write", "1", false, true},
		{"dry_run", "1", true, false},
		{"writes disabled", "", false, false},
	}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			root, results, amend := applyEnv(t)
			t.Setenv("HDF_MCP_ENABLE_WRITES", m.writes)
			before, _ := os.ReadFile(filepath.Join(root, results))

			res, out := callApply(t, applyInput(results, amend, "merged.json", m.dry))
			if res != nil {
				t.Fatalf("apply must not error: %s", payloadText(t, res))
			}

			after, _ := os.ReadFile(filepath.Join(root, results))
			if string(before) != string(after) {
				t.Fatal("the results input file must be byte-unchanged")
			}
			_, statErr := os.Stat(filepath.Join(root, "merged.json"))
			if m.writeOK {
				if statErr != nil {
					t.Fatalf("expected merged output file: %v (out=%+v)", statErr, out)
				}
				if out.OutputPath != "merged.json" {
					t.Fatalf("output path should be the distinct merged file: %+v", out)
				}
			} else if !os.IsNotExist(statErr) {
				t.Fatal("no file should be written in this mode")
			}
		})
	}
}

// TestApplyAmendment_RejectsOverwritingInput guards the AC hard: an output that
// resolves to the results input path is refused in any mode.
func TestApplyAmendment_RejectsOverwritingInput(t *testing.T) {
	_, results, amend := applyEnv(t)
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	res, _ := callApply(t, applyInput(results, amend, results, false))
	if res == nil || !res.IsError {
		t.Fatal("writing over the results input path must be refused")
	}
}

// refuseOverwritingInput must use device+inode identity, not lexical equality:
// an in-root symlink or hardlink alias of the input has a different path string
// but the same underlying file, so a lexical-only guard would let apply truncate
// the input through the alias.
func TestRefuseOverwritingInput_SymlinkAlias(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	if err := os.WriteFile(filepath.Join(root, "results.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "results.json"), filepath.Join(root, "alias.json")); err != nil {
		t.Fatal(err)
	}
	if terr := refuseOverwritingInput("alias.json", "results.json"); terr == nil {
		t.Fatal("writing through a symlink alias of the input must be refused")
	}
}

func TestRefuseOverwritingInput_HardlinkAlias(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	if err := os.WriteFile(filepath.Join(root, "results.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "results.json"), filepath.Join(root, "hard.json")); err != nil {
		t.Fatal(err)
	}
	if terr := refuseOverwritingInput("hard.json", "results.json"); terr == nil {
		t.Fatal("writing through a hardlink alias of the input must be refused")
	}
}

func TestRefuseOverwritingInput_DistinctAndMissingAllowed(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	if err := os.WriteFile(filepath.Join(root, "results.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A different existing file must be allowed.
	if err := os.WriteFile(filepath.Join(root, "other.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if terr := refuseOverwritingInput("other.json", "results.json"); terr != nil {
		t.Fatalf("a distinct existing output must be allowed: %v", terr)
	}
	// A not-yet-created output must be allowed (no stat crash; lexical stands).
	if terr := refuseOverwritingInput("new-output.json", "results.json"); terr != nil {
		t.Fatalf("a not-yet-created output must be allowed: %v", terr)
	}
	// The lexical fast-path still refuses the identical path even with no file.
	if terr := refuseOverwritingInput("ghost.json", "ghost.json"); terr == nil {
		t.Fatal("identical output/input path must be refused by the lexical pre-check")
	}
}

// TestAttributionSurvivesApply — the applied results file carries
// statusOverrides[].appliedBy on the affected requirement.
func TestAttributionSurvivesApply(t *testing.T) {
	root, results, amend := applyEnv(t)
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	_, out := callApply(t, applyInput(results, amend, "merged.json", false))
	if out.OutputPath == "" {
		t.Fatalf("expected a write: %+v", out)
	}
	req := firstRequirement(t, filepath.Join(root, "merged.json"))
	// The computed effective fields land on the applied requirement.
	if req["effectiveStatus"] != "passed" || req["disposition"] != "waiver" {
		t.Fatalf("effectiveStatus/disposition not applied: %v", req)
	}
	ovs, ok := req["statusOverrides"].([]any)
	if !ok || len(ovs) == 0 {
		t.Fatalf("applied requirement must retain statusOverrides: %v", req)
	}
	ab, _ := ovs[0].(map[string]any)["appliedBy"].(map[string]any)
	if ab == nil || ab["identifier"] != "admin@example.com" {
		t.Fatalf("appliedBy attribution must survive on the applied file: %v", ovs[0])
	}
}

// TestApplyAmendment_ComplianceDelta — the before/after projected compliance and
// changed-requirement count reflect the waiver (0% → 100%, one requirement).
func TestApplyAmendment_ComplianceDelta(t *testing.T) {
	_, results, amend := applyEnv(t)
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	_, out := callApply(t, applyInput(results, amend, "merged.json", false))
	if out.ProjectedCompliance.Before != 0 || out.ProjectedCompliance.After != 100 {
		t.Fatalf("compliance delta wrong: %+v", out.ProjectedCompliance)
	}
	if out.ChangedRequirementCount != 1 {
		t.Fatalf("changedRequirementCount = %d, want 1", out.ChangedRequirementCount)
	}
	if !out.Valid || out.Handle == "" || out.Sha256 == "" {
		t.Fatalf("summary must carry valid + handle + sha256: %+v", out)
	}
}

// TestApplyAmendment_DryRunReturnsDelta — dry_run returns the delta and changed
// count WITHOUT writing (the check-before-commit).
func TestApplyAmendment_DryRunReturnsDelta(t *testing.T) {
	root, results, amend := applyEnv(t)
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	_, out := callApply(t, applyInput(results, amend, "merged.json", true))
	if out.OutputPath != "" || out.Notice == "" {
		t.Fatalf("dry_run must not write + must carry a notice: %+v", out)
	}
	if out.ProjectedCompliance.After != 100 || out.ChangedRequirementCount != 1 {
		t.Fatalf("dry_run must still compute the delta: %+v", out)
	}
	if _, err := os.Stat(filepath.Join(root, "merged.json")); !os.IsNotExist(err) {
		t.Fatal("dry_run must not create a file")
	}
}

func TestApplyAmendment_WritesDisabled(t *testing.T) {
	_, results, amend := applyEnv(t)
	t.Setenv("HDF_MCP_ENABLE_WRITES", "")
	_, out := callApply(t, applyInput(results, amend, "merged.json", false))
	if out.OutputPath != "" || !out.WritesDisabled || !strings.Contains(out.Notice, "WRITES_DISABLED") {
		t.Fatalf("writes-disabled must preview, not write: %+v", out)
	}
	if out.ProjectedCompliance.After != 100 {
		t.Fatal("writes-disabled must still compute the delta")
	}
}

// TestApplyAmendment_Deterministic — same inputs twice yields byte-identical
// merged output.
func TestApplyAmendment_Deterministic(t *testing.T) {
	root, results, amend := applyEnv(t)
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	callApply(t, applyInput(results, amend, "a.json", false))
	callApply(t, applyInput(results, amend, "b.json", false))
	a, _ := os.ReadFile(filepath.Join(root, "a.json"))
	b, _ := os.ReadFile(filepath.Join(root, "b.json"))
	if string(a) != string(b) {
		t.Fatal("apply must be deterministic (byte-identical output)")
	}
}

func TestApplyAmendment_WrongResultsDocType(t *testing.T) {
	_, results, amend := applyEnv(t)
	// Swap the args: the amendments doc is not a results doc.
	res, _ := callApply(t, applyInput(amend, amend, "", false))
	if res == nil || !res.IsError {
		t.Fatal("a non-results document in the results slot must be refused")
	}
	_ = results
}

func TestApplyAmendment_WrongAmendmentsDocType(t *testing.T) {
	_, results, _ := applyEnv(t)
	res, _ := callApply(t, applyInput(results, results, "", false))
	if res == nil || !res.IsError {
		t.Fatal("a non-amendments document in the amendments slot must be refused")
	}
}

func TestApplyAmendment_PureCompute_NoWrite(t *testing.T) {
	_, results, amend := applyEnv(t)
	_, out := callApply(t, applyInput(results, amend, "", false))
	if out.OutputPath != "" || out.Notice != "" {
		t.Fatalf("no output → no write, no notice: %+v", out)
	}
	if out.ProjectedCompliance.After != 100 || out.Handle == "" {
		t.Fatalf("pure compute must still return the delta + handle: %+v", out)
	}
}

func TestApplyAmendment_HandleInput(t *testing.T) {
	root, results, amend := applyEnv(t)
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	// Mint handles the way hdf_open would, then apply via handles.
	ldr := loader.New(0, 0, 0)
	rData, _ := os.ReadFile(filepath.Join(root, results))
	aData, _ := os.ReadFile(filepath.Join(root, amend))
	rr, _ := ldr.Load(rData)
	ar, _ := ldr.Load(aData)
	rh, _ := handle.Encode(handle.Compute(results, rData, rr.DocType, "test"))
	ah, _ := handle.Encode(handle.Compute(amend, aData, ar.DocType, "test"))
	_, out := callApply(t, applyAmendmentInput{
		Results:    handle.Source{Handle: rh},
		Amendments: handle.Source{Handle: ah},
		Output:     "merged.json",
	})
	if !out.Valid || out.ProjectedCompliance.After != 100 {
		t.Fatalf("handle inputs must apply the same as path inputs: %+v", out)
	}
}

func TestApplyAmendment_DraftRefused(t *testing.T) {
	root, results, _ := applyEnv(t)
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	draft := `{"name":"D","_draft":true,"overrides":[{"type":"waiver","requirementId":"AC-1","status":"passed","reason":"x","appliedBy":{"type":"agent","identifier":"a"},"appliedAt":"2026-03-01T00:00:00Z","expiresAt":"2099-12-31T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(root, "draft.json"), []byte(draft), 0o600); err != nil {
		t.Fatal(err)
	}
	res, _ := callApply(t, applyInput(results, "draft.json", "merged.json", false))
	if res == nil || !res.IsError {
		t.Fatal("an incomplete draft amendment must be refused")
	}
}

func TestApplyAmendment_OutputPathDenied(t *testing.T) {
	_, results, amend := applyEnv(t)
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	res, _ := callApply(t, applyInput(results, amend, "../../../etc/x.json", false))
	if res == nil || !res.IsError {
		t.Fatal("an output escaping HDF_MCP_ROOT must be denied")
	}
}

func TestApplyAmendment_ResultsNotFound(t *testing.T) {
	_, _, amend := applyEnv(t)
	res, _ := callApply(t, applyInput("nonexistent.json", amend, "", false))
	if res == nil || !res.IsError {
		t.Fatal("a missing results source must be an error")
	}
}

// A results-shaped but schema-invalid input (requirement missing required tags)
// produces invalid merged output — it must be refused (SCHEMA_INVALID) and never
// written.
func TestApplyAmendment_RefusesInvalidMergedResults(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HDF_MCP_ROOT", root)
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	badResults := `{"baselines":[{"name":"b","requirements":[{"id":"AC-1","impact":0.5,"title":"t","descriptions":[{"label":"default","data":"d"}],"results":[{"status":"failed","codeDesc":"c","startTime":"2026-01-01T00:00:00Z"}]}]}],"statistics":{"duration":0.1}}`
	if err := os.WriteFile(filepath.Join(root, "bad.json"), []byte(badResults), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "amend.json"), []byte(applyAmendmentsDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	res, _ := callApply(t, applyInput("bad.json", "amend.json", "merged.json", false))
	if res == nil || !res.IsError || !strings.Contains(payloadText(t, res), "SCHEMA_INVALID") {
		t.Fatalf("invalid merged results must be refused: %s", payloadTextOrEmpty(res))
	}
	if _, err := os.Stat(filepath.Join(root, "merged.json")); !os.IsNotExist(err) {
		t.Fatal("a refused apply must not write")
	}
}

func TestApplySummary_InvalidBytesHandled(t *testing.T) {
	if _, terr := applySummary([]byte("not json"), []byte("{}")); terr == nil {
		t.Fatal("invalid before bytes must surface an error")
	}
	if _, terr := applySummary([]byte("{}"), []byte("not json")); terr == nil {
		t.Fatal("invalid after bytes must surface an error")
	}
}

func firstRequirement(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	bl := doc["baselines"].([]any)[0].(map[string]any)
	return bl["requirements"].([]any)[0].(map[string]any)
}

// TestApplyAmendment_ErrorNextCallNamesOwnInputs — a document-not-found error
// from apply_amendment must name the slot the caller actually passed (results /
// amendments), never `source`, which this tool has no input for (jobi.4 / D3).
func TestApplyAmendment_ErrorNextCallNamesOwnInputs(t *testing.T) {
	_, results, amend := applyEnv(t)

	res, _ := callApply(t, applyInput(results, "nonexistent.json", "", false))
	tr := toolResultPayload(t, res)
	if !strings.Contains(tr.NextCall, "amendments") {
		t.Errorf("amendments-not-found nextCall must name `amendments`, got %q", tr.NextCall)
	}
	if strings.Contains(tr.NextCall, "source") {
		t.Errorf("nextCall leaked `source` — apply_amendment has no source input: %q", tr.NextCall)
	}

	res2, _ := callApply(t, applyInput("nonexistent.json", amend, "", false))
	tr2 := toolResultPayload(t, res2)
	if !strings.Contains(tr2.NextCall, "results") {
		t.Errorf("results-not-found nextCall must name `results`, got %q", tr2.NextCall)
	}
	if strings.Contains(tr2.NextCall, "source") {
		t.Errorf("nextCall leaked `source`: %q", tr2.NextCall)
	}
}
