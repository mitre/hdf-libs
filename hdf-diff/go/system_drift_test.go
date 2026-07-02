package diff

import (
	"testing"
)

// -- Fixtures -----------------------------------------------------------------

func systemV1Fixture() map[string]any {
	return map[string]any{
		"name":                "Portal-Prod",
		"authorizationStatus": "authorized",
		"categorizationLevel": "moderate",
		"components": []any{
			map[string]any{
				"name":         "WebTier",
				"type":         "application",
				"baselineRefs": []any{"RHEL9-STIG"},
				"description":  "Web servers",
			},
			map[string]any{
				"name":         "DatabaseTier",
				"type":         "database",
				"baselineRefs": []any{"PostgreSQL-STIG"},
				"description":  "Database servers",
			},
			map[string]any{
				"name":        "LegacyAPI",
				"type":        "service",
				"description": "Old API being decommissioned",
			},
		},
	}
}

func systemV2Fixture() map[string]any {
	return map[string]any{
		"name":                "Portal-Prod",
		"authorizationStatus": "conditionallyAuthorized",
		"categorizationLevel": "moderate",
		"components": []any{
			map[string]any{
				"name":         "WebTier",
				"type":         "application",
				"baselineRefs": []any{"RHEL9-STIG", "Container-STIG"},
				"description":  "Web servers (containerized)",
			},
			map[string]any{
				"name":         "DatabaseTier",
				"type":         "database",
				"baselineRefs": []any{"PostgreSQL-STIG"},
				"description":  "Database servers",
			},
			map[string]any{
				"name":        "CacheTier",
				"type":        "application",
				"description": "New Redis cache layer",
			},
		},
	}
}

func findComponentDiff(diffs []ComponentDiff, name string) *ComponentDiff {
	for i := range diffs {
		if diffs[i].Name == name {
			return &diffs[i]
		}
	}
	return nil
}

// -- Tests --------------------------------------------------------------------

func TestDiffSystems_ComparisonMode(t *testing.T) {
	result, err := DiffSystems(systemV1Fixture(), systemV2Fixture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ComparisonMode != ModeSystemDrift {
		t.Errorf("expected comparisonMode %q, got %q", ModeSystemDrift, result.ComparisonMode)
	}
}

func TestDiffSystems_FormatVersion(t *testing.T) {
	result, err := DiffSystems(systemV1Fixture(), systemV2Fixture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FormatVersion != version100 {
		t.Errorf("expected formatVersion %q, got %q", version100, result.FormatVersion)
	}
}

func TestDiffSystems_Timestamp(t *testing.T) {
	result, err := DiffSystems(systemV1Fixture(), systemV2Fixture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Timestamp == "" {
		t.Error("expected timestamp to be set")
	}
}

func TestDiffSystems_Sources(t *testing.T) {
	result, err := DiffSystems(systemV1Fixture(), systemV2Fixture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(result.Sources))
	}
	if result.Sources[0].Role != RoleOld {
		t.Errorf("expected source[0] role %q, got %q", RoleOld, result.Sources[0].Role)
	}
	if result.Sources[1].Role != RoleNew {
		t.Errorf("expected source[1] role %q, got %q", RoleNew, result.Sources[1].Role)
	}
	if result.Sources[0].Label != "Portal-Prod (old)" {
		t.Errorf("expected source[0] label %q, got %q", "Portal-Prod (old)", result.Sources[0].Label)
	}
	if result.Sources[1].Label != "Portal-Prod (new)" {
		t.Errorf("expected source[1] label %q, got %q", "Portal-Prod (new)", result.Sources[1].Label)
	}
}

func TestDiffSystems_WebTierUpdated(t *testing.T) {
	result, err := DiffSystems(systemV1Fixture(), systemV2Fixture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	comp := findComponentDiff(result.ComponentDiffs, "WebTier")
	if comp == nil {
		t.Fatal("WebTier not found")
	}
	if comp.State != StateUpdated {
		t.Errorf("expected WebTier state %q, got %q", StateUpdated, comp.State)
	}
}

func TestDiffSystems_DatabaseTierUnchanged(t *testing.T) {
	result, err := DiffSystems(systemV1Fixture(), systemV2Fixture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	comp := findComponentDiff(result.ComponentDiffs, "DatabaseTier")
	if comp == nil {
		t.Fatal("DatabaseTier not found")
	}
	if comp.State != StateUnchanged {
		t.Errorf("expected DatabaseTier state %q, got %q", StateUnchanged, comp.State)
	}
}

func TestDiffSystems_LegacyAPIAbsent(t *testing.T) {
	result, err := DiffSystems(systemV1Fixture(), systemV2Fixture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	comp := findComponentDiff(result.ComponentDiffs, "LegacyAPI")
	if comp == nil {
		t.Fatal("LegacyAPI not found")
	}
	if comp.State != StateAbsent {
		t.Errorf("expected LegacyAPI state %q, got %q", StateAbsent, comp.State)
	}
	if comp.Before == nil {
		t.Error("expected before to be non-nil")
	}
	if comp.After != nil {
		t.Error("expected after to be nil")
	}
}

func TestDiffSystems_CacheTierNew(t *testing.T) {
	result, err := DiffSystems(systemV1Fixture(), systemV2Fixture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	comp := findComponentDiff(result.ComponentDiffs, "CacheTier")
	if comp == nil {
		t.Fatal("CacheTier not found")
	}
	if comp.State != StateNew {
		t.Errorf("expected CacheTier state %q, got %q", StateNew, comp.State)
	}
	if comp.Before != nil {
		t.Error("expected before to be nil")
	}
	if comp.After == nil {
		t.Error("expected after to be non-nil")
	}
}

func TestDiffSystems_WebTierFieldChanges(t *testing.T) {
	result, err := DiffSystems(systemV1Fixture(), systemV2Fixture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	comp := findComponentDiff(result.ComponentDiffs, "WebTier")
	if comp == nil {
		t.Fatal("WebTier not found")
	}
	if len(comp.FieldChanges) < 2 {
		t.Errorf("expected at least 2 field changes, got %d", len(comp.FieldChanges))
	}

	changedPaths := make(map[string]bool)
	for _, fc := range comp.FieldChanges {
		changedPaths[fc.Path] = true
	}
	for _, expectedPath := range []string{"baselineRefs", "description"} {
		if !changedPaths[expectedPath] {
			t.Errorf("expected field change for %q, not found", expectedPath)
		}
	}
}

func TestDiffSystems_AuthorizationStatusChange(t *testing.T) {
	result, err := DiffSystems(systemV1Fixture(), systemV2Fixture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Extensions == nil {
		t.Fatal("expected extensions to be set")
	}
	sysChanges, ok := result.Extensions["systemFieldChanges"].([]FieldChange)
	if !ok {
		t.Fatal("expected systemFieldChanges in extensions")
	}
	found := false
	for _, fc := range sysChanges {
		if fc.Path == "authorizationStatus" {
			found = true
			if fc.Op != OpReplace {
				t.Errorf("expected op %q, got %q", OpReplace, fc.Op)
			}
			if fc.OldValue != "authorized" {
				t.Errorf("expected oldValue %q, got %v", "authorized", fc.OldValue)
			}
			if fc.NewValue != "conditionallyAuthorized" {
				t.Errorf("expected newValue %q, got %v", "conditionallyAuthorized", fc.NewValue)
			}
		}
	}
	if !found {
		t.Error("authorizationStatus change not found in system field changes")
	}
}

func TestDiffSystems_NoExtensionsWhenIdentical(t *testing.T) {
	v1 := systemV1Fixture()
	result, err := DiffSystems(v1, v1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Extensions != nil {
		t.Error("expected extensions to be nil for identical systems")
	}
}

func TestDiffSystems_SummaryCounts(t *testing.T) {
	result, err := DiffSystems(systemV1Fixture(), systemV2Fixture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := result.Summary
	if s.Total != 4 {
		t.Errorf("expected total 4, got %d", s.Total)
	}
	if s.MatchedCount != 2 {
		t.Errorf("expected matchedCount 2, got %d", s.MatchedCount)
	}
	if s.UnmatchedOldCount != 1 {
		t.Errorf("expected unmatchedOldCount 1, got %d", s.UnmatchedOldCount)
	}
	if s.UnmatchedNewCount != 1 {
		t.Errorf("expected unmatchedNewCount 1, got %d", s.UnmatchedNewCount)
	}
	if s.Updated != 1 {
		t.Errorf("expected updated 1, got %d", s.Updated)
	}
	if s.Unchanged != 1 {
		t.Errorf("expected unchanged 1, got %d", s.Unchanged)
	}
	if s.Absent != 1 {
		t.Errorf("expected absent 1, got %d", s.Absent)
	}
	if s.New != 1 {
		t.Errorf("expected new 1, got %d", s.New)
	}
	if s.Fixed != 0 {
		t.Errorf("expected fixed 0, got %d", s.Fixed)
	}
	if s.Regressed != 0 {
		t.Errorf("expected regressed 0, got %d", s.Regressed)
	}
}

func TestDiffSystems_EmptyRequirementAndBaselineDiffs(t *testing.T) {
	result, err := DiffSystems(systemV1Fixture(), systemV2Fixture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RequirementDiffs) != 0 {
		t.Errorf("expected 0 requirementDiffs, got %d", len(result.RequirementDiffs))
	}
	if len(result.BaselineDiffs) != 0 {
		t.Errorf("expected 0 baselineDiffs, got %d", len(result.BaselineDiffs))
	}
}

func TestDiffSystems_IdenticalSystems(t *testing.T) {
	v1 := systemV1Fixture()
	result, err := DiffSystems(v1, v1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, comp := range result.ComponentDiffs {
		if comp.State != StateUnchanged {
			t.Errorf("expected all components unchanged, got %q for %s", comp.State, comp.Name)
		}
	}
}

func TestDiffSystems_ComponentDiffsSortedByName(t *testing.T) {
	result, err := DiffSystems(systemV1Fixture(), systemV2Fixture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := 1; i < len(result.ComponentDiffs); i++ {
		if result.ComponentDiffs[i].Name < result.ComponentDiffs[i-1].Name {
			t.Errorf("componentDiffs not sorted: %q comes after %q",
				result.ComponentDiffs[i].Name, result.ComponentDiffs[i-1].Name)
		}
	}
}

// -- ComponentId matching tests -----------------------------------------------

func TestDiffSystems_MatchByComponentId(t *testing.T) {
	// Components renamed but same componentId → should match as updated, not absent+new
	oldSys := map[string]any{
		"name": "Test-System",
		"components": []any{
			map[string]any{
				"componentId": "uuid-web-001",
				"name":        "WebTier-Old",
				"type":        "application",
				"description": "Web servers v1",
			},
		},
	}
	newSys := map[string]any{
		"name": "Test-System",
		"components": []any{
			map[string]any{
				"componentId": "uuid-web-001",
				"name":        "WebTier-New",
				"type":        "application",
				"description": "Web servers v2",
			},
		},
	}

	result, err := DiffSystems(oldSys, newSys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.ComponentDiffs) != 1 {
		t.Fatalf("expected 1 component diff, got %d", len(result.ComponentDiffs))
	}

	cd := result.ComponentDiffs[0]
	// Should use the new name when componentId matches
	if cd.Name != "WebTier-New" {
		t.Errorf("expected component name 'WebTier-New', got %q", cd.Name)
	}
	if cd.State != StateUpdated {
		t.Errorf("expected state 'updated' (description changed), got %q", cd.State)
	}

	// Should NOT have absent + new (which would happen with name-only matching)
	for _, d := range result.ComponentDiffs {
		if d.State == StateAbsent || d.State == StateNew {
			t.Errorf("unexpected state %q for %q — componentId should have matched", d.State, d.Name)
		}
	}
}

func TestDiffSystems_ComponentIdTakesPrecedenceOverName(t *testing.T) {
	// Two components: one matched by componentId (renamed), one by name
	oldSys := map[string]any{
		"name": "Test-System",
		"components": []any{
			map[string]any{
				"componentId": "uuid-001",
				"name":        "OldName",
				"type":        "application",
			},
			map[string]any{
				"name":        "SharedName",
				"type":        "database",
				"description": "Matched by name",
			},
		},
	}
	newSys := map[string]any{
		"name": "Test-System",
		"components": []any{
			map[string]any{
				"componentId": "uuid-001",
				"name":        "NewName",
				"type":        "application",
			},
			map[string]any{
				"name":        "SharedName",
				"type":        "database",
				"description": "Matched by name",
			},
		},
	}

	result, err := DiffSystems(oldSys, newSys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have exactly 2 component diffs (not 3 from absent OldName + new NewName + matched SharedName)
	if len(result.ComponentDiffs) != 2 {
		t.Fatalf("expected 2 component diffs, got %d", len(result.ComponentDiffs))
	}

	// Verify no absent or new states
	for _, cd := range result.ComponentDiffs {
		if cd.State == StateAbsent || cd.State == StateNew {
			t.Errorf("unexpected state %q for %q", cd.State, cd.Name)
		}
	}
}

// -- Component BOM drift tests ------------------------------------------------

func TestDiffSystems_BomsFieldChange(t *testing.T) {
	bomOld := map[string]any{"bomType": "sbom", "format": "cyclonedx", "ref": "https://artifacts.example.gov/webapp-1.0.cdx.json"}
	bomNew := map[string]any{"bomType": "sbom", "format": "cyclonedx", "ref": "https://artifacts.example.gov/webapp-2.0.cdx.json"}
	oldSys := map[string]any{
		"name": "System",
		"components": []any{
			map[string]any{"componentId": "comp-1", "name": "WebApp", "type": "application", "boms": []any{bomOld}},
		},
	}
	newSys := map[string]any{
		"name": "System",
		"components": []any{
			map[string]any{"componentId": "comp-1", "name": "WebApp", "type": "application", "boms": []any{bomNew}},
		},
	}

	result, err := DiffSystems(oldSys, newSys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	comp := findComponentDiff(result.ComponentDiffs, "WebApp")
	if comp == nil {
		t.Fatal("WebApp not found")
	}
	if comp.State != StateUpdated {
		t.Errorf("expected state %q, got %q", StateUpdated, comp.State)
	}
	var bomsChange *FieldChange
	for i := range comp.FieldChanges {
		if comp.FieldChanges[i].Path == "boms" {
			bomsChange = &comp.FieldChanges[i]
		}
	}
	if bomsChange == nil {
		t.Fatal("expected a field change for 'boms'")
	}
	if bomsChange.Op != OpReplace {
		t.Errorf("expected op %q, got %q", OpReplace, bomsChange.Op)
	}
}

func TestDiffSystems_BomsUnchanged(t *testing.T) {
	bom := map[string]any{"bomType": "sbom", "format": "cyclonedx", "ref": "https://artifacts.example.gov/webapp-1.0.cdx.json"}
	sys := map[string]any{
		"name": "System",
		"components": []any{
			map[string]any{"componentId": "comp-1", "name": "WebApp", "type": "application", "boms": []any{bom}},
		},
	}

	result, err := DiffSystems(sys, sys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	comp := findComponentDiff(result.ComponentDiffs, "WebApp")
	if comp == nil {
		t.Fatal("WebApp not found")
	}
	if comp.State != StateUnchanged {
		t.Errorf("expected state %q, got %q", StateUnchanged, comp.State)
	}
}

// Fields outside systemTrackedFields (e.g. the former SBOM ref field removed in
// ADR-0001) must never surface as component drift.
func TestDiffSystems_UntrackedFieldNoDrift(t *testing.T) {
	oldSys := map[string]any{
		"name": "System",
		"components": []any{
			map[string]any{"componentId": "comp-1", "name": "WebApp", "type": "application", "owner": "team-a"},
		},
	}
	newSys := map[string]any{
		"name": "System",
		"components": []any{
			map[string]any{"componentId": "comp-1", "name": "WebApp", "type": "application", "owner": "team-b"},
		},
	}

	result, err := DiffSystems(oldSys, newSys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	comp := findComponentDiff(result.ComponentDiffs, "WebApp")
	if comp == nil {
		t.Fatal("WebApp not found")
	}
	if comp.State != StateUnchanged {
		t.Errorf("expected state %q, got %q", StateUnchanged, comp.State)
	}
	if len(comp.FieldChanges) != 0 {
		t.Errorf("expected 0 field changes, got %d", len(comp.FieldChanges))
	}
}

// -- Data flow diffing tests --------------------------------------------------

func TestDiffSystems_DataFlowAdded(t *testing.T) {
	oldSys := map[string]any{
		"name":       "Test-System",
		"components": []any{},
	}
	newSys := map[string]any{
		"name":       "Test-System",
		"components": []any{},
		"dataFlows": []any{
			map[string]any{
				"from":     "web-001",
				"to":       "db-001",
				"protocol": "tcp",
			},
		},
	}

	result, err := DiffSystems(oldSys, newSys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Extensions == nil {
		t.Fatal("expected extensions with dataFlowChanges")
	}
	dfChanges, ok := result.Extensions["dataFlowChanges"]
	if !ok {
		t.Fatal("expected dataFlowChanges in extensions")
	}
	changes, ok := dfChanges.([]DataFlowChange)
	if !ok {
		t.Fatalf("expected []DataFlowChange, got %T", dfChanges)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 data flow change, got %d", len(changes))
	}
	if changes[0].State != "added" {
		t.Errorf("expected state 'added', got %q", changes[0].State)
	}
}

func TestDiffSystems_DataFlowRemoved(t *testing.T) {
	oldSys := map[string]any{
		"name":       "Test-System",
		"components": []any{},
		"dataFlows": []any{
			map[string]any{
				"from":     "web-001",
				"to":       "db-001",
				"protocol": "tcp",
			},
		},
	}
	newSys := map[string]any{
		"name":       "Test-System",
		"components": []any{},
	}

	result, err := DiffSystems(oldSys, newSys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Extensions == nil {
		t.Fatal("expected extensions with dataFlowChanges")
	}
	changes := result.Extensions["dataFlowChanges"].([]DataFlowChange)
	if len(changes) != 1 {
		t.Fatalf("expected 1 data flow change, got %d", len(changes))
	}
	if changes[0].State != "removed" {
		t.Errorf("expected state 'removed', got %q", changes[0].State)
	}
}

func TestDiffSystems_DataFlowUpdated(t *testing.T) {
	oldSys := map[string]any{
		"name":       "Test-System",
		"components": []any{},
		"dataFlows": []any{
			map[string]any{
				"from":     "web-001",
				"to":       "db-001",
				"protocol": "tcp",
			},
		},
	}
	newSys := map[string]any{
		"name":       "Test-System",
		"components": []any{},
		"dataFlows": []any{
			map[string]any{
				"from":     "web-001",
				"to":       "db-001",
				"protocol": "tls",
			},
		},
	}

	result, err := DiffSystems(oldSys, newSys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Extensions == nil {
		t.Fatal("expected extensions with dataFlowChanges")
	}
	changes := result.Extensions["dataFlowChanges"].([]DataFlowChange)
	if len(changes) != 1 {
		t.Fatalf("expected 1 data flow change, got %d", len(changes))
	}
	if changes[0].State != "updated" {
		t.Errorf("expected state 'updated', got %q", changes[0].State)
	}
}

func TestDiffSystems_NoDataFlowChanges_NoExtension(t *testing.T) {
	oldSys := map[string]any{
		"name":       "Test-System",
		"components": []any{},
		"dataFlows": []any{
			map[string]any{
				"from":     "web-001",
				"to":       "db-001",
				"protocol": "tcp",
			},
		},
	}

	result, err := DiffSystems(oldSys, oldSys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Extensions != nil {
		if _, ok := result.Extensions["dataFlowChanges"]; ok {
			t.Error("expected no dataFlowChanges extension when flows are identical")
		}
	}
}
