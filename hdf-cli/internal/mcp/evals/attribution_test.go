package evals

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestAttribution_AuthorStampsAgent — every override hdf_author emits on the
// judgment path carries appliedBy.type="agent", and a model-supplied type is
// overridden by the server (§3: the agent-override count stays honest).
func TestAttribution_AuthorStampsAgent(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	root := stageRoot(t)
	// The model tries to claim a non-agent identity.
	driveCalls(t, []call{{"hdf_author", map[string]any{
		"docType": "amendments", "name": "A",
		"content": []any{map[string]any{
			"type": "riskAdjustment", "requirementId": "V-1", "status": "notApplicable",
			"reason": "compensating control", "expiresAt": "2099-12-31T00:00:00Z",
			"appliedBy": map[string]any{"identifier": "jdoe", "type": "username"},
		}},
		"output": "amendments.json",
	}}})
	var doc map[string]any
	b, err := os.ReadFile(filepath.Join(root, "amendments.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	ov := doc["overrides"].([]any)[0].(map[string]any)
	ab := ov["appliedBy"].(map[string]any)
	if ab["type"] != "agent" {
		t.Fatalf("server must stamp appliedBy.type=agent, got %v", ab["type"])
	}
	if ov["appliedAt"] == nil || ov["appliedAt"] == "" {
		t.Fatal("server must stamp appliedAt")
	}
}

// TestAttribution_ComplianceReportsAgentCount — hdf_compliance surfaces the
// agent-attributed override count (system/human overrides excluded).
func TestAttribution_ComplianceReportsAgentCount(t *testing.T) {
	stageRoot(t, [2]string{fxAgentOverrides, "r.json"})
	sc := structured(t, driveCalls(t, []call{{"hdf_compliance", map[string]any{
		"source": map[string]any{"path": "r.json"},
	}}})[0])
	ao, ok := sc["agentOverrides"].(map[string]any)
	if !ok {
		t.Fatalf("hdf_compliance must report an agentOverrides block: %v", sc)
	}
	if cnt, _ := ao["count"].(float64); cnt != 1 {
		t.Fatalf("agentOverrides.count = %v, want 1 (system override excluded)", ao["count"])
	}
}

// TestAttribution_ApplyReportsComplianceDelta — hdf_apply_amendment reports the
// before/after projected compliance against its target (§3).
func TestAttribution_ApplyReportsComplianceDelta(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	stageRoot(t, [2]string{fxVEX, "vex.json"}, [2]string{fxVexResults, "results.json"})
	driveCalls(t, []call{{"hdf_author", map[string]any{
		"docType": "amendments", "name": "V", "source": map[string]any{"path": "vex.json"},
		"expiresAt": "2099-12-31T00:00:00Z", "output": "amendments.json"}}})
	sc := structured(t, driveCalls(t, []call{{"hdf_apply_amendment", map[string]any{
		"results": map[string]any{"path": "results.json"}, "amendments": map[string]any{"path": "amendments.json"},
	}}})[0])
	pc, ok := sc["projectedCompliance"].(map[string]any)
	if !ok {
		t.Fatalf("apply must report projectedCompliance: %v", sc)
	}
	before, _ := pc["before"].(float64)
	after, _ := pc["after"].(float64)
	if !(after > before) {
		t.Fatalf("applying the VEX amendment must improve compliance: before=%v after=%v", before, after)
	}
}
