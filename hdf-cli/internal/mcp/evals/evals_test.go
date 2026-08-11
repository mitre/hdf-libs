package evals

import "testing"

// Eval 1 — summarize the components in an HDF system document.
// A single hdf_inspect call yields the component inventory (count + type
// breakdown + system name); the summary an agent gives names that inventory.
func TestEval_SummarizeSystemComponents(t *testing.T) {
	stageRoot(t, [2]string{fxSystem, "system.json"})
	res := runTranscript(t, "summarize-system-components",
		[]call{{Tool: "hdf_inspect", Args: map[string]any{"source": map[string]any{"path": "system.json"}}}},
		500,
		func(responses []string) error {
			// Portal Prod has 2 application-type components.
			return answerContains(responses, "Portal Prod", "application", `"count":2`)
		},
	)
	t.Logf("tokens=%d/%d", res.TotalTokens, res.Budget)
}

// Eval 2 — find notReviewed results in a results doc AND draft attestation
// amendments for them. hdf_query surfaces the notReviewed requirement; hdf_author
// drafts a schema-valid attestation amendment (server stamps appliedBy.type=agent).
func TestEval_NotReviewedToAttestation(t *testing.T) {
	stageRoot(t, [2]string{fxCklResults, "results.json"})
	res := runTranscript(t, "notreviewed-to-attestation",
		[]call{
			{Tool: "hdf_query", Args: map[string]any{"source": map[string]any{"path": "results.json"}, "status": []any{"notReviewed"}}},
			{Tool: "hdf_author", Args: map[string]any{
				"docType": "amendments", "name": "Attestations",
				"content": []any{map[string]any{
					"type": "attestation", "requirementId": "V-251559", "status": "passed",
					"reason":    "Manually verified by the assessor; control is implemented.",
					"expiresAt": "2099-12-31T00:00:00Z",
				}},
			}},
		},
		950,
		func(responses []string) error {
			return answerContains(responses, "V-251559", `"docType":"amendments"`, `"valid":true`)
		},
	)
	t.Logf("tokens=%d/%d", res.TotalTokens, res.Budget)
}

// Eval 3 — summarize the changes in an HDF diff. hdf_diff computes the temporal
// comparison; the summary names the fixed and regressed requirements.
func TestEval_SummarizeDiff(t *testing.T) {
	stageRoot(t, [2]string{fxDiffFrom, "from.json"}, [2]string{fxDiffTo, "to.json"})
	res := runTranscript(t, "summarize-diff",
		[]call{{Tool: "hdf_diff", Args: map[string]any{
			"from": map[string]any{"path": "from.json"}, "to": map[string]any{"path": "to.json"},
		}}},
		950,
		func(responses []string) error {
			return answerContains(responses, "V-FIX-01", "fixed", "V-REG-02", "regressed")
		},
	)
	t.Logf("tokens=%d/%d", res.TotalTokens, res.Budget)
}

// Eval 6 — apply a VEX doc as amendments to a results doc. hdf_author derives
// amendments from the real VEX (from_vex path), then hdf_apply_amendment applies
// them to a results doc, flipping the not_affected finding to passed. Two staged
// driveCalls barrier between the write and the read (the second reads the file
// the first wrote).
func TestEval_ApplyVexAsAmendments(t *testing.T) {
	stageRoot(t, [2]string{fxVEX, "vex.json"}, [2]string{fxVexResults, "results.json"})
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	authorResp := driveCalls(t, []call{{Tool: "hdf_author", Args: map[string]any{
		"docType": "amendments", "name": "From VEX",
		"source": map[string]any{"path": "vex.json"}, "expiresAt": "2099-12-31T00:00:00Z",
		"output": "amendments.json",
	}}})
	applyResp := driveCalls(t, []call{{Tool: "hdf_apply_amendment", Args: map[string]any{
		"results":    map[string]any{"path": "results.json"},
		"amendments": map[string]any{"path": "amendments.json"},
		"output":     "applied.json",
	}}})
	res := replayResponses(t, "apply-vex-as-amendments", append(authorResp, applyResp...), 1000,
		func(responses []string) error {
			// From VEX → amendments authored; applying flips CVE-2024-1000 to passed
			// (the poam on CVE-2024-2000 stays failed) → exactly one changed.
			return answerContains(responses, `"docType":"amendments"`, `"changedRequirementCount":1`, `"valid":true`)
		})
	t.Logf("tokens=%d/%d", res.TotalTokens, res.Budget)
}

// Eval 4 — parse an hdf-plan doc (so an agent can suggest testing tools to
// implement it). hdf_inspect surfaces the plan name and its assessment count.
func TestEval_ParsePlan(t *testing.T) {
	stageRoot(t, [2]string{fxPlan, "plan.json"})
	res := runTranscript(t, "parse-plan",
		[]call{{Tool: "hdf_inspect", Args: map[string]any{"source": map[string]any{"path": "plan.json"}}}},
		500,
		func(responses []string) error {
			return answerContains(responses, "portal-prod-assessment-plan", `"docType":"plan"`, `"count":2`)
		},
	)
	t.Logf("tokens=%d/%d", res.TotalTokens, res.Budget)
}
