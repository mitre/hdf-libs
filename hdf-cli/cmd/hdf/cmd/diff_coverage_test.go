//nolint:dupl
package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mitre/hdf-cli/pkg/diff/sbom"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Unit tests for truncate ---

func TestDiffCoverage_Truncate(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"short string unchanged", "hello", 10, "hello"},
		{"exact length unchanged", "hello", 5, "hello"},
		{"truncated with ellipsis", "hello world", 8, "hello..."},
		{"maxLen 3 no ellipsis", "hello", 3, "hel"},
		{"maxLen 2 no ellipsis", "hello", 2, "he"},
		{"maxLen 1 no ellipsis", "hello", 1, "h"},
		{"maxLen 0", "hello", 0, ""},
		{"empty string", "", 5, ""},
		{"maxLen 4 with ellipsis", "hello world", 4, "h..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncate(tt.input, tt.maxLen)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- Unit tests for getRequirementTitle ---

func TestDiffCoverage_GetRequirementTitle(t *testing.T) {
	t.Run("nil title returns empty string", func(t *testing.T) {
		req := hdf.EvaluatedRequirement{Title: nil}
		assert.Equal(t, "", getRequirementTitle(req))
	})

	t.Run("non-nil title returns value", func(t *testing.T) {
		title := "My Requirement Title"
		req := hdf.EvaluatedRequirement{Title: &title}
		assert.Equal(t, "My Requirement Title", getRequirementTitle(req))
	})

	t.Run("empty string title returns empty", func(t *testing.T) {
		title := ""
		req := hdf.EvaluatedRequirement{Title: &title}
		assert.Equal(t, "", getRequirementTitle(req))
	})
}

// --- Unit tests for outputDiffNameOnly ---

func TestDiffCoverage_OutputDiffNameOnly(t *testing.T) {
	result := diffResult{
		Requirements: []diffRequirement{
			{ID: "REQ-001", State: diffFixed},
			{ID: "REQ-002", State: diffUnchanged},
			{ID: "REQ-003", State: diffRegressed},
			{ID: "REQ-004", State: diffNew},
			{ID: "REQ-005", State: diffAbsent},
			{ID: "REQ-006", State: diffUpdated},
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	outputDiffNameOnly(result)

	_ = w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Should include changed IDs (not unchanged)
	assert.Contains(t, output, "REQ-001")
	assert.NotContains(t, output, "REQ-002") // unchanged should be excluded
	assert.Contains(t, output, "REQ-003")
	assert.Contains(t, output, "REQ-004")
	assert.Contains(t, output, "REQ-005")
	assert.Contains(t, output, "REQ-006")
}

// --- Unit tests for groupByLabel ---

func TestDiffCoverage_GroupByLabel(t *testing.T) {
	t.Run("groups by label from baseline extensions", func(t *testing.T) {
		oldResults := hdf.HdfResults{
			Baselines: []hdf.EvaluatedBaseline{
				{
					Name: "baseline-a",
					Extensions: map[string]interface{}{
						"labels": map[string]interface{}{
							"env": "production",
						},
					},
					Requirements: []hdf.EvaluatedRequirement{
						makeMinimalEvalReq("REQ-001", "passed"),
					},
				},
			},
		}
		newResults := hdf.HdfResults{
			Baselines: []hdf.EvaluatedBaseline{
				{
					Name: "baseline-a",
					Extensions: map[string]interface{}{
						"labels": map[string]interface{}{
							"env": "production",
						},
					},
					Requirements: []hdf.EvaluatedRequirement{
						makeMinimalEvalReq("REQ-001", "passed"),
					},
				},
			},
		}

		result := diffResult{
			Requirements: []diffRequirement{
				{ID: "REQ-001", State: diffUnchanged, Baseline: "baseline-a"},
			},
		}

		summaries := groupByLabel("env", oldResults, newResults, result)
		require.Len(t, summaries, 1)
		assert.Equal(t, "production", summaries[0].Name)
		assert.Equal(t, []string{"baseline-a"}, summaries[0].BaselineRefs)
	})

	t.Run("unlabeled baseline grouped as (unlabeled)", func(t *testing.T) {
		oldResults := hdf.HdfResults{
			Baselines: []hdf.EvaluatedBaseline{
				{
					Name:         "baseline-a",
					Requirements: []hdf.EvaluatedRequirement{},
				},
			},
		}
		newResults := hdf.HdfResults{
			Baselines: []hdf.EvaluatedBaseline{
				{
					Name:         "baseline-a",
					Requirements: []hdf.EvaluatedRequirement{},
				},
			},
		}

		result := diffResult{
			Requirements: []diffRequirement{
				{ID: "REQ-001", State: diffUnchanged, Baseline: "baseline-a"},
			},
		}

		summaries := groupByLabel("env", oldResults, newResults, result)
		require.Len(t, summaries, 1)
		assert.Equal(t, "(unlabeled)", summaries[0].Name)
	})

	t.Run("multiple groups sorted by name", func(t *testing.T) {
		oldResults := hdf.HdfResults{
			Baselines: []hdf.EvaluatedBaseline{
				{
					Name: "baseline-z",
					Extensions: map[string]interface{}{
						"labels": map[string]interface{}{
							"tier": "web",
						},
					},
					Requirements: []hdf.EvaluatedRequirement{
						makeMinimalEvalReq("REQ-001", "failed"),
					},
				},
				{
					Name: "baseline-a",
					Extensions: map[string]interface{}{
						"labels": map[string]interface{}{
							"tier": "database",
						},
					},
					Requirements: []hdf.EvaluatedRequirement{
						makeMinimalEvalReq("REQ-002", "passed"),
					},
				},
			},
		}
		newResults := hdf.HdfResults{
			Baselines: []hdf.EvaluatedBaseline{
				{
					Name: "baseline-z",
					Extensions: map[string]interface{}{
						"labels": map[string]interface{}{
							"tier": "web",
						},
					},
					Requirements: []hdf.EvaluatedRequirement{
						makeMinimalEvalReq("REQ-001", "passed"),
					},
				},
				{
					Name: "baseline-a",
					Extensions: map[string]interface{}{
						"labels": map[string]interface{}{
							"tier": "database",
						},
					},
					Requirements: []hdf.EvaluatedRequirement{
						makeMinimalEvalReq("REQ-002", "passed"),
					},
				},
			},
		}

		result := diffResult{
			Requirements: []diffRequirement{
				{ID: "REQ-001", State: diffFixed, Baseline: "baseline-z"},
				{ID: "REQ-002", State: diffUnchanged, Baseline: "baseline-a"},
			},
		}

		summaries := groupByLabel("tier", oldResults, newResults, result)
		require.Len(t, summaries, 2)
		assert.Equal(t, "database", summaries[0].Name)
		assert.Equal(t, "web", summaries[1].Name)
	})
}

// --- Unit tests for applyGroupBy ---

func TestDiffCoverage_ApplyGroupBy(t *testing.T) {
	oldResults := hdf.HdfResults{
		Baselines: []hdf.EvaluatedBaseline{
			{
				Name: "baseline-a",
				Extensions: map[string]interface{}{
					"labels": map[string]interface{}{
						"env": "prod",
					},
				},
				Requirements: []hdf.EvaluatedRequirement{
					makeMinimalEvalReq("REQ-001", "passed"),
				},
			},
		},
	}
	newResults := oldResults

	result := diffResult{
		Requirements: []diffRequirement{
			{ID: "REQ-001", State: diffUnchanged, Baseline: "baseline-a"},
		},
	}

	t.Run("group-by baseline", func(t *testing.T) {
		summaries := applyGroupBy("baseline", oldResults, newResults, result)
		require.Len(t, summaries, 1)
		assert.Equal(t, "baseline-a", summaries[0].Name)
	})

	t.Run("group-by label key", func(t *testing.T) {
		summaries := applyGroupBy("env", oldResults, newResults, result)
		require.Len(t, summaries, 1)
		assert.Equal(t, "prod", summaries[0].Name)
	})

	t.Run("group-by labels.env prefix stripped", func(t *testing.T) {
		summaries := applyGroupBy("labels.env", oldResults, newResults, result)
		require.Len(t, summaries, 1)
		assert.Equal(t, "prod", summaries[0].Name)
	})

	t.Run("group-by unknown label falls to unlabeled", func(t *testing.T) {
		summaries := applyGroupBy("nonexistent", oldResults, newResults, result)
		require.Len(t, summaries, 1)
		assert.Equal(t, "(unlabeled)", summaries[0].Name)
	})
}

// --- Unit tests for renderDiffOutput ---

func TestDiffCoverage_RenderDiffOutput(t *testing.T) {
	filtered := diffResult{
		FormatVersion:  "1.0.0",
		ComparisonMode: "temporal",
		Summary:        diffSummary{Total: 1, Fixed: 1},
		Requirements: []diffRequirement{
			{ID: "REQ-001", State: diffFixed, OldStatus: "failed", NewStatus: "passed", Title: "Test Requirement"},
		},
	}

	t.Run("name-only output", func(t *testing.T) {
		flags := &diffFlags{nameOnly: true}
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := renderDiffOutput(filtered, flags, "old.json", "new.json")

		_ = w.Close()
		os.Stdout = oldStdout

		require.NoError(t, err)
		buf := make([]byte, 4096)
		n, _ := r.Read(buf)
		output := string(buf[:n])
		assert.Contains(t, output, "REQ-001")
	})

	t.Run("stat output", func(t *testing.T) {
		flags := &diffFlags{stat: true}
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := renderDiffOutput(filtered, flags, "old.json", "new.json")

		_ = w.Close()
		os.Stdout = oldStdout

		require.NoError(t, err)
		buf := make([]byte, 4096)
		n, _ := r.Read(buf)
		output := string(buf[:n])
		assert.Contains(t, output, "1 fixed")
	})

	t.Run("json format via flag", func(t *testing.T) {
		flags := &diffFlags{format: "json"}
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := renderDiffOutput(filtered, flags, "old.json", "new.json")

		_ = w.Close()
		os.Stdout = oldStdout

		require.NoError(t, err)
		buf := make([]byte, 4096)
		n, _ := r.Read(buf)
		output := string(buf[:n])

		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(output), &parsed))
		assert.Equal(t, "1.0.0", parsed["formatVersion"])
	})

	t.Run("markdown format", func(t *testing.T) {
		flags := &diffFlags{format: "markdown"}
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := renderDiffOutput(filtered, flags, "old.json", "new.json")

		_ = w.Close()
		os.Stdout = oldStdout

		require.NoError(t, err)
		buf := make([]byte, 4096)
		n, _ := r.Read(buf)
		output := string(buf[:n])
		assert.Contains(t, output, "## HDF Comparison")
		assert.Contains(t, output, "|")
	})

	t.Run("default table format", func(t *testing.T) {
		flags := &diffFlags{format: "table"}
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := renderDiffOutput(filtered, flags, "old.json", "new.json")

		_ = w.Close()
		os.Stdout = oldStdout

		require.NoError(t, err)
		buf := make([]byte, 4096)
		n, _ := r.Read(buf)
		output := string(buf[:n])
		assert.Contains(t, output, "HDF Comparison")
	})
}

// --- Unit tests for outputSbomJSON ---

func TestDiffCoverage_OutputSbomJSON(t *testing.T) {
	result := &sbom.DiffResult{
		PackageDiffs: []sbom.PackageDiff{
			{Name: "pkg-a", State: "added", NewVersion: "1.0.0"},
			{Name: "pkg-b", State: "removed", OldVersion: "2.0.0"},
		},
		Added:   1,
		Removed: 1,
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputSbomJSON(result)

	_ = w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)
	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(output), &parsed))
	assert.Equal(t, float64(1), parsed["added"])
	assert.Equal(t, float64(1), parsed["removed"])

	diffs, ok := parsed["packageDiffs"].([]interface{})
	require.True(t, ok)
	assert.Len(t, diffs, 2)
}

// --- Unit tests for outputSbomTable ---

func TestDiffCoverage_OutputSbomTable(t *testing.T) {
	result := &sbom.DiffResult{
		PackageDiffs: []sbom.PackageDiff{
			{Name: "pkg-add", State: "added", NewVersion: "1.0.0"},
			{Name: "pkg-rem", State: "removed", OldVersion: "2.0.0"},
			{Name: "pkg-upd", State: "updated", OldVersion: "1.0.0", NewVersion: "2.0.0"},
			{Name: "pkg-unch", State: "unchanged"},
		},
		Added:     1,
		Removed:   1,
		Updated:   1,
		Unchanged: 1,
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	outputSbomTable(result, "old-sbom.json", "new-sbom.json")

	_ = w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	assert.Contains(t, output, "SBOM Comparison")
	assert.Contains(t, output, "old-sbom.json")
	assert.Contains(t, output, "new-sbom.json")
	assert.Contains(t, output, "pkg-add")
	assert.Contains(t, output, "pkg-rem")
	assert.Contains(t, output, "pkg-upd")
	// Check state labels
	assert.Contains(t, output, "added")
	assert.Contains(t, output, "removed")
	assert.Contains(t, output, "updated")
	// Updated should show version transition
	assert.Contains(t, output, "1.0.0")
	assert.Contains(t, output, "2.0.0")
	// Summary line
	assert.Contains(t, output, "1 added")
	assert.Contains(t, output, "1 removed")
	assert.Contains(t, output, "1 updated")
	assert.Contains(t, output, "1 unchanged")
}

// --- CLI-level SBOM diff tests ---

func TestDiffCoverage_SbomDiff_CLI(t *testing.T) {
	// CycloneDX 1.5 SBOM with metadata.component (required by protobom)
	oldSBOM := map[string]interface{}{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
		"version":      1,
		"metadata": map[string]interface{}{
			"timestamp": "2024-01-01T00:00:00Z",
			"component": map[string]interface{}{
				"type":    "application",
				"bom-ref": "test-app",
				"name":    "test-app",
				"version": "1.0.0",
			},
		},
		"components": []interface{}{
			map[string]interface{}{
				"type":    "library",
				"bom-ref": "lodash-ref",
				"name":    "lodash",
				"version": "4.17.20",
			},
			map[string]interface{}{
				"type":    "library",
				"bom-ref": "express-ref",
				"name":    "express",
				"version": "4.17.1",
			},
		},
	}
	newSBOM := map[string]interface{}{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000002",
		"version":      1,
		"metadata": map[string]interface{}{
			"timestamp": "2024-02-01T00:00:00Z",
			"component": map[string]interface{}{
				"type":    "application",
				"bom-ref": "test-app",
				"name":    "test-app",
				"version": "1.0.0",
			},
		},
		"components": []interface{}{
			map[string]interface{}{
				"type":    "library",
				"bom-ref": "lodash-ref",
				"name":    "lodash",
				"version": "4.17.21",
			},
			map[string]interface{}{
				"type":    "library",
				"bom-ref": "axios-ref",
				"name":    "axios",
				"version": "0.21.1",
			},
		},
	}

	oldPath := writeJSONFixture(t, oldSBOM)
	newPath := writeJSONFixture(t, newSBOM)

	t.Run("sbom table output", func(t *testing.T) {
		stdout, stderr, err := executeCommand("diff", "--sbom", oldPath, newPath)
		allowExitCode(t, err, stderr)
		assert.Contains(t, stdout, "SBOM Comparison")
		assert.Contains(t, stdout, "Summary:")
	})

	t.Run("sbom json output", func(t *testing.T) {
		stdout, stderr, err := executeCommand("diff", "--sbom", "-f", "json", oldPath, newPath)
		allowExitCode(t, err, stderr)
		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(stdout), &parsed))
		assert.Contains(t, parsed, "packageDiffs")
		assert.Contains(t, parsed, "added")
	})

	t.Run("sbom quiet mode", func(t *testing.T) {
		stdout, _, err := executeCommand("diff", "--sbom", "-q", oldPath, newPath)
		if err != nil {
			t.Logf("quiet mode returned error (expected for exit code): %v", err)
		}
		// Quiet mode should suppress output
		assert.Empty(t, strings.TrimSpace(stdout))
	})
}

func TestDiffCoverage_SbomDiff_MissingFile(t *testing.T) {
	validPath := writeJSONFixture(t, map[string]interface{}{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000003",
		"version":      1,
		"metadata": map[string]interface{}{
			"component": map[string]interface{}{
				"type": "application", "bom-ref": "test", "name": "test", "version": "1.0.0",
			},
		},
		"components": []interface{}{},
	})

	t.Run("missing old file", func(t *testing.T) {
		_, _, err := executeCommand("diff", "--sbom", "nonexistent.json", validPath)
		require.Error(t, err)
	})

	t.Run("missing new file", func(t *testing.T) {
		_, _, err := executeCommand("diff", "--sbom", validPath, "nonexistent.json")
		require.Error(t, err)
	})
}

func TestDiffCoverage_SbomDiff_InvalidSBOM(t *testing.T) {
	tmpDir := t.TempDir()
	invalidPath := filepath.Join(tmpDir, "invalid.json")
	require.NoError(t, os.WriteFile(invalidPath, []byte("not valid json at all"), 0o600))

	validPath := writeJSONFixture(t, map[string]interface{}{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000004",
		"version":      1,
		"metadata": map[string]interface{}{
			"component": map[string]interface{}{
				"type": "application", "bom-ref": "test", "name": "test", "version": "1.0.0",
			},
		},
		"components": []interface{}{},
	})

	_, _, err := executeCommand("diff", "--sbom", invalidPath, validPath)
	require.Error(t, err)
}

// --- CLI-level tests for --name-only ---

func TestDiffCoverage_NameOnly_CLI(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	stdout, stderr, err := executeCommand("diff", "--name-only", oldPath, newPath)
	allowExitCode(t, err, stderr)

	// Should list changed requirement IDs
	assert.Contains(t, stdout, "REQ-001") // fixed
	assert.Contains(t, stdout, "REQ-002") // regressed
	assert.Contains(t, stdout, "REQ-004") // absent
	assert.Contains(t, stdout, "REQ-005") // new
	// Should NOT list unchanged
	assert.NotContains(t, stdout, "REQ-003") // unchanged
}

// --- loadDiffInputs error paths ---

func TestDiffCoverage_LoadDiffInputs_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Invalid JSON in old file
	badOld := filepath.Join(tmpDir, "bad-old.json")
	require.NoError(t, os.WriteFile(badOld, []byte("{invalid json}"), 0o600))

	goodPath := writeHDFFixture(t, syntheticHDFBefore())

	_, _, err := loadDiffInputs(badOld, goodPath)
	require.Error(t, err)

	// Invalid JSON in new file
	badNew := filepath.Join(tmpDir, "bad-new.json")
	require.NoError(t, os.WriteFile(badNew, []byte("{invalid json}"), 0o600))

	_, _, err = loadDiffInputs(goodPath, badNew)
	require.Error(t, err)
}

func TestDiffCoverage_LoadDiffInputs_NonexistentFiles(t *testing.T) {
	goodPath := writeHDFFixture(t, syntheticHDFBefore())

	_, _, err := loadDiffInputs("nonexistent-old.json", goodPath)
	require.Error(t, err)

	_, _, err = loadDiffInputs(goodPath, "nonexistent-new.json")
	require.Error(t, err)
}

// --- CLI-level tests for group-by with labels ---

func TestDiffCoverage_GroupByLabel_CLI(t *testing.T) {
	// Build fixtures with labels in extensions
	oldFixture := map[string]interface{}{
		"baselines": []interface{}{
			map[string]interface{}{
				"name":     "baseline-a",
				"checksum": map[string]interface{}{"algorithm": "sha256", "value": "aaa"},
				"extensions": map[string]interface{}{
					"labels": map[string]interface{}{
						"env": "production",
					},
				},
				"requirements": []interface{}{
					makeRequirementWithResultStatus("REQ-001", "failed"),
				},
			},
		},
		"components": []interface{}{},
		"statistics": map[string]interface{}{},
	}
	newFixture := map[string]interface{}{
		"baselines": []interface{}{
			map[string]interface{}{
				"name":     "baseline-a",
				"checksum": map[string]interface{}{"algorithm": "sha256", "value": "bbb"},
				"extensions": map[string]interface{}{
					"labels": map[string]interface{}{
						"env": "production",
					},
				},
				"requirements": []interface{}{
					makeRequirementWithResultStatus("REQ-001", "passed"),
				},
			},
		},
		"components": []interface{}{},
		"statistics": map[string]interface{}{},
	}

	oldPath := writeHDFFixture(t, oldFixture)
	newPath := writeHDFFixture(t, newFixture)

	stdout, stderr, err := executeCommand("diff", "--group-by", "env", oldPath, newPath)
	allowExitCode(t, err, stderr)

	assert.Contains(t, stdout, "production")
	assert.Contains(t, stdout, "Old Compliance")
}

// --- Quiet mode tests ---

func TestDiffCoverage_QuietMode(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	stdout, _, err := executeCommand("diff", "-q", oldPath, newPath)
	// quiet implies exit-code, so differences should produce an error
	require.Error(t, err)
	// stdout should be empty in quiet mode
	assert.Empty(t, strings.TrimSpace(stdout))
}

// --- Component summaries rendering tests ---

func TestDiffCoverage_RenderDiffOutput_WithComponentSummaries(t *testing.T) {
	filtered := diffResult{
		FormatVersion:  "1.0.0",
		ComparisonMode: "temporal",
		Summary:        diffSummary{Total: 2, Fixed: 1, Unchanged: 1},
		Requirements: []diffRequirement{
			{ID: "REQ-001", State: diffFixed, OldStatus: "failed", NewStatus: "passed", Baseline: "baseline-a"},
			{ID: "REQ-002", State: diffUnchanged, OldStatus: "passed", NewStatus: "passed", Baseline: "baseline-a"},
		},
		ComponentSummaries: []componentSummary{
			{
				Name:            "WebTier",
				BaselineRefs:    []string{"baseline-a"},
				Summary:         diffSummary{Total: 2, Fixed: 1, Unchanged: 1},
				OldCompliance:   50,
				NewCompliance:   100,
				ComplianceDelta: 50,
			},
		},
	}

	t.Run("table format with component summaries", func(t *testing.T) {
		flags := &diffFlags{format: "table"}
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := renderDiffOutput(filtered, flags, "old.json", "new.json")

		_ = w.Close()
		os.Stdout = oldStdout

		require.NoError(t, err)
		buf := make([]byte, 8192)
		n, _ := r.Read(buf)
		output := string(buf[:n])
		assert.Contains(t, output, "WebTier")
		assert.Contains(t, output, "Old Compliance")
	})

	t.Run("markdown format with component summaries", func(t *testing.T) {
		flags := &diffFlags{format: "markdown"}
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := renderDiffOutput(filtered, flags, "old.json", "new.json")

		_ = w.Close()
		os.Stdout = oldStdout

		require.NoError(t, err)
		buf := make([]byte, 8192)
		n, _ := r.Read(buf)
		output := string(buf[:n])
		assert.Contains(t, output, "WebTier")
	})
}

// --- makeMinimalEvalReq helper ---

// makeMinimalEvalReq creates a minimal EvaluatedRequirement suitable for unit testing.
func makeMinimalEvalReq(id, status string) hdf.EvaluatedRequirement {
	code := ""
	rs := hdf.ResultStatus(status)
	return hdf.EvaluatedRequirement{
		ID:           id,
		Impact:       0.5,
		Code:         &code,
		Tags:         map[string]interface{}{},
		Descriptions: []hdf.Description{{Label: "default", Data: "test"}},
		Results: []hdf.RequirementResult{
			{
				Status:    &rs,
				CodeDesc:  "synthetic check",
				StartTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}
}
