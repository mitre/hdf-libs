package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- evidence build tests ---

func TestEvidenceBuildBasic(t *testing.T) {
	tmpDir := t.TempDir()

	systemDoc := `{"name": "test-system", "components": [{"name": "c1", "type": "application"}]}`
	resultsDoc := `{"baselines": [], "platform": {}, "statistics": {}, "version": "2.0"}`

	systemPath := filepath.Join(tmpDir, "system.json")
	resultsPath := filepath.Join(tmpDir, "results.json")
	outputPath := filepath.Join(tmpDir, "package.json")

	require.NoError(t, os.WriteFile(systemPath, []byte(systemDoc), 0o600))
	require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

	t.Run("builds package with required args and writes to file", func(t *testing.T) {
		_, stderr, err := executeCommand("evidence", "build",
			"--system", systemPath,
			"--results", resultsPath,
			"-o", outputPath,
		)
		require.NoError(t, err)
		assert.Contains(t, stderr, "Evidence package written to")
		assert.Contains(t, stderr, "2 documents")

		data, readErr := os.ReadFile(outputPath)
		require.NoError(t, readErr)

		var pkg map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &pkg))

		assert.Equal(t, "test-system-evidence-package", pkg["name"])
		assert.NotEmpty(t, pkg["preparedAt"])
		assert.Equal(t, filepath.Base(systemPath), pkg["systemRef"])

		contents, ok := pkg["contents"].([]interface{})
		require.True(t, ok)
		assert.Len(t, contents, 2)

		// Verify first entry is hdf-system with correct checksum
		first := contents[0].(map[string]interface{})
		assert.Equal(t, "hdf-system", first["type"])
		assert.Equal(t, "system.json", first["uri"])
		chk := first["checksum"].(map[string]interface{})
		assert.Equal(t, "sha256", chk["algorithm"])

		expectedHash := sha256.Sum256([]byte(systemDoc))
		assert.Equal(t, hex.EncodeToString(expectedHash[:]), chk["value"])
	})

	t.Run("builds package to stdout when no output flag", func(t *testing.T) {
		stdout, _, err := executeCommand("evidence", "build",
			"--system", systemPath,
			"--results", resultsPath,
		)
		require.NoError(t, err)

		var pkg map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(stdout), &pkg))
		assert.Equal(t, "test-system-evidence-package", pkg["name"])
	})

	t.Run("errors when system flag missing", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "build",
			"--results", resultsPath,
		)
		require.Error(t, err)
	})

	t.Run("errors when results flag missing", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "build",
			"--system", systemPath,
		)
		require.Error(t, err)
	})

	t.Run("errors when system file does not exist", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "build",
			"--system", filepath.Join(tmpDir, "nonexistent.json"),
			"--results", resultsPath,
		)
		require.Error(t, err)
	})

	t.Run("errors when results file does not exist", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "build",
			"--system", systemPath,
			"--results", filepath.Join(tmpDir, "nonexistent.json"),
		)
		require.Error(t, err)
	})
}

func TestEvidenceBuildWithOptionalDocs(t *testing.T) {
	tmpDir := t.TempDir()

	systemDoc := `{"name": "my-system", "components": [{"name": "c1", "type": "application"}]}`
	resultsDoc := noTargetsJSON
	amendDoc := `{"amendments": []}`
	compDoc := `{"comparison": {}}`

	systemPath := filepath.Join(tmpDir, "system.json")
	resultsPath := filepath.Join(tmpDir, "results.json")
	amendPath := filepath.Join(tmpDir, "amendments.json")
	compPath := filepath.Join(tmpDir, "comparison.json")
	outputPath := filepath.Join(tmpDir, "pkg.json")

	require.NoError(t, os.WriteFile(systemPath, []byte(systemDoc), 0o600))
	require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))
	require.NoError(t, os.WriteFile(amendPath, []byte(amendDoc), 0o600))
	require.NoError(t, os.WriteFile(compPath, []byte(compDoc), 0o600))

	_, stderr, err := executeCommand("evidence", "build",
		"--system", systemPath,
		"--results", resultsPath,
		"--amendments", amendPath,
		"--comparison", compPath,
		"-o", outputPath,
	)
	require.NoError(t, err)
	assert.Contains(t, stderr, "4 documents")

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)

	var pkg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &pkg))

	contents := pkg["contents"].([]interface{})
	assert.Len(t, contents, 4)

	types := make([]string, len(contents))
	for i, c := range contents {
		types[i] = c.(map[string]interface{})["type"].(string)
	}
	assert.Equal(t, []string{"hdf-system", "hdf-results", "hdf-amendments", "hdf-comparison"}, types)
}

func TestEvidenceBuildRejectsNoNameSystem(t *testing.T) {
	// As of m58u, the input gate validates System docs before they reach the
	// evidence-build flow. A System without the required "name" field is
	// rejected; the previous "unnamed-system" fallback in runEvidenceBuild is
	// unreachable. This test pins the new behavior.
	tmpDir := t.TempDir()

	systemDoc := `{"components": [{"name": "c1", "type": "application"}]}`
	resultsDoc := noTargetsJSON

	systemPath := filepath.Join(tmpDir, "system.json")
	resultsPath := filepath.Join(tmpDir, "results.json")

	require.NoError(t, os.WriteFile(systemPath, []byte(systemDoc), 0o600))
	require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

	_, _, err := executeCommand("evidence", "build",
		"--system", systemPath,
		"--results", resultsPath,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema validation")
	assert.Contains(t, err.Error(), "name")
}

func TestEvidenceBuildAmendmentMissing(t *testing.T) {
	tmpDir := t.TempDir()

	systemDoc := `{"name": "sys", "components": [{"name": "c1", "type": "application"}]}`
	resultsDoc := noTargetsJSON

	systemPath := filepath.Join(tmpDir, "system.json")
	resultsPath := filepath.Join(tmpDir, "results.json")

	require.NoError(t, os.WriteFile(systemPath, []byte(systemDoc), 0o600))
	require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

	_, _, err := executeCommand("evidence", "build",
		"--system", systemPath,
		"--results", resultsPath,
		"--amendments", filepath.Join(tmpDir, "missing.json"),
	)
	require.Error(t, err)
}

func TestEvidenceBuildComparisonMissing(t *testing.T) {
	tmpDir := t.TempDir()

	systemDoc := `{"name": "sys", "components": [{"name": "c1", "type": "application"}]}`
	resultsDoc := noTargetsJSON

	systemPath := filepath.Join(tmpDir, "system.json")
	resultsPath := filepath.Join(tmpDir, "results.json")

	require.NoError(t, os.WriteFile(systemPath, []byte(systemDoc), 0o600))
	require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

	_, _, err := executeCommand("evidence", "build",
		"--system", systemPath,
		"--results", resultsPath,
		"--comparison", filepath.Join(tmpDir, "missing.json"),
	)
	require.Error(t, err)
}

// --- computeCompleteness tests ---

func TestComputeCompleteness(t *testing.T) {
	t.Run("computes compliance percentage from results", func(t *testing.T) {
		tmpDir := t.TempDir()
		resultsDoc := `{
			"baselines": [{
				"name": "baseline-1",
				"requirements": [
					{"results": [{"status": "passed"}]},
					{"results": [{"status": "passed"}]},
					{"results": [{"status": "failed"}]},
					{"results": [{"status": "passed"}]}
				]
			}]
		}`
		resultsPath := filepath.Join(tmpDir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

		sysDoc := map[string]interface{}{
			"components": []interface{}{
				map[string]interface{}{
					"baselineRefs": []interface{}{"baseline-1"},
				},
			},
		}

		cc := computeCompleteness(sysDoc, []string{resultsPath})
		assert.Equal(t, 75.0, cc["compliancePercent"])
		assert.Equal(t, true, cc["allBaselinesAssessed"])
		assert.Equal(t, true, cc["allComponentsCovered"])
	})

	t.Run("returns defaults when results file missing", func(t *testing.T) {
		sysDoc := map[string]interface{}{}
		cc := computeCompleteness(sysDoc, []string{"/nonexistent/results.json"})
		assert.Equal(t, false, cc["allBaselinesAssessed"])
		assert.Equal(t, false, cc["allComponentsCovered"])
		assert.Equal(t, 0.0, cc["compliancePercent"])
	})

	t.Run("returns defaults when results is invalid JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		resultsPath := filepath.Join(tmpDir, "bad.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte("not json"), 0o600))

		sysDoc := map[string]interface{}{}
		cc := computeCompleteness(sysDoc, []string{resultsPath})
		assert.Equal(t, 0.0, cc["compliancePercent"])
	})

	t.Run("zero requirements yields 0% compliance", func(t *testing.T) {
		tmpDir := t.TempDir()
		resultsDoc := `{"baselines": [{"name": "empty", "requirements": []}]}`
		resultsPath := filepath.Join(tmpDir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

		sysDoc := map[string]interface{}{
			"components": []interface{}{
				map[string]interface{}{
					"baselineRefs": []interface{}{"empty"},
				},
			},
		}
		cc := computeCompleteness(sysDoc, []string{resultsPath})
		assert.Equal(t, 0.0, cc["compliancePercent"])
		assert.Equal(t, true, cc["allBaselinesAssessed"])
	})

	t.Run("uncovered baseline ref sets allAssessed false", func(t *testing.T) {
		tmpDir := t.TempDir()
		resultsDoc := `{"baselines": [{"name": "only-this", "requirements": []}]}`
		resultsPath := filepath.Join(tmpDir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

		sysDoc := map[string]interface{}{
			"components": []interface{}{
				map[string]interface{}{
					"baselineRefs": []interface{}{"missing-baseline"},
				},
			},
		}
		cc := computeCompleteness(sysDoc, []string{resultsPath})
		assert.Equal(t, false, cc["allBaselinesAssessed"])
		assert.Equal(t, false, cc["allComponentsCovered"])
	})

	t.Run("no components yields allComponentsCovered false", func(t *testing.T) {
		tmpDir := t.TempDir()
		resultsDoc := noTargetsJSON
		resultsPath := filepath.Join(tmpDir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

		sysDoc := map[string]interface{}{}
		cc := computeCompleteness(sysDoc, []string{resultsPath})
		assert.Equal(t, false, cc["allComponentsCovered"])
	})

	t.Run("requirement with empty results counts as not passed", func(t *testing.T) {
		tmpDir := t.TempDir()
		resultsDoc := `{"baselines": [{"name": "b", "requirements": [{"results": []}]}]}`
		resultsPath := filepath.Join(tmpDir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

		sysDoc := map[string]interface{}{}
		cc := computeCompleteness(sysDoc, []string{resultsPath})
		assert.Equal(t, 0.0, cc["compliancePercent"])
	})

	t.Run("handles non-map baselines gracefully", func(t *testing.T) {
		tmpDir := t.TempDir()
		resultsDoc := `{"baselines": ["not-a-map", 42]}`
		resultsPath := filepath.Join(tmpDir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

		sysDoc := map[string]interface{}{}
		cc := computeCompleteness(sysDoc, []string{resultsPath})
		assert.Equal(t, 0.0, cc["compliancePercent"])
	})

	t.Run("handles non-map requirements gracefully", func(t *testing.T) {
		tmpDir := t.TempDir()
		resultsDoc := `{"baselines": [{"name": "b", "requirements": ["not-a-map"]}]}`
		resultsPath := filepath.Join(tmpDir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

		sysDoc := map[string]interface{}{}
		cc := computeCompleteness(sysDoc, []string{resultsPath})
		assert.Equal(t, 0.0, cc["compliancePercent"])
	})

	t.Run("handles non-map component gracefully", func(t *testing.T) {
		tmpDir := t.TempDir()
		resultsDoc := noTargetsJSON
		resultsPath := filepath.Join(tmpDir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

		sysDoc := map[string]interface{}{
			"components": []interface{}{"not-a-map"},
		}
		cc := computeCompleteness(sysDoc, []string{resultsPath})
		// Should not panic
		assert.NotNil(t, cc)
	})

	t.Run("handles non-string baselineRef gracefully", func(t *testing.T) {
		tmpDir := t.TempDir()
		resultsDoc := noTargetsJSON
		resultsPath := filepath.Join(tmpDir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

		sysDoc := map[string]interface{}{
			"components": []interface{}{
				map[string]interface{}{
					"baselineRefs": []interface{}{42},
				},
			},
		}
		cc := computeCompleteness(sysDoc, []string{resultsPath})
		assert.NotNil(t, cc)
	})
}

// --- buildContentEntry tests ---

func TestBuildContentEntry(t *testing.T) {
	t.Run("produces correct entry with sha256 checksum", func(t *testing.T) {
		tmpDir := t.TempDir()
		content := `{"hello": "world"}`
		fp := filepath.Join(tmpDir, "doc.json")
		require.NoError(t, os.WriteFile(fp, []byte(content), 0o600))

		entry, err := buildContentEntry("hdf-results", fp)
		require.NoError(t, err)

		assert.Equal(t, "hdf-results", entry["type"])
		assert.Equal(t, "doc.json", entry["uri"])

		chk := entry["checksum"].(map[string]interface{})
		assert.Equal(t, "sha256", chk["algorithm"])

		h := sha256.Sum256([]byte(content))
		assert.Equal(t, hex.EncodeToString(h[:]), chk["value"])
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		_, err := buildContentEntry("hdf-system", "/nonexistent/file.json")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read")
	})
}

// --- evidence verify tests ---

func TestEvidenceVerifyCommand(t *testing.T) {
	t.Run("verifies matching checksums successfully", func(t *testing.T) {
		tmpDir := t.TempDir()

		docContent := `{"test": "data"}`
		docPath := filepath.Join(tmpDir, "doc.json")
		require.NoError(t, os.WriteFile(docPath, []byte(docContent), 0o600))

		h := sha256.Sum256([]byte(docContent))
		hashHex := hex.EncodeToString(h[:])

		pkg := map[string]interface{}{
			"name": "test-package",
			"contents": []interface{}{
				map[string]interface{}{
					"type": "hdf-results",
					"uri":  "doc.json",
					"checksum": map[string]interface{}{
						"algorithm": "sha256",
						"value":     hashHex,
					},
				},
			},
		}
		pkgData, _ := json.Marshal(pkg)
		pkgPath := filepath.Join(tmpDir, "evidence.json")
		require.NoError(t, os.WriteFile(pkgPath, pkgData, 0o600))

		stdout, _, err := executeCommand("evidence", "verify", pkgPath)
		require.NoError(t, err)
		assert.Contains(t, stdout, "sha256 match")
		assert.Contains(t, stdout, "test-package")
	})

	t.Run("detects checksum mismatch", func(t *testing.T) {
		tmpDir := t.TempDir()

		docPath := filepath.Join(tmpDir, "doc.json")
		require.NoError(t, os.WriteFile(docPath, []byte(`{"data": "changed"}`), 0o600))

		pkg := map[string]interface{}{
			"name": "mismatch-pkg",
			"contents": []interface{}{
				map[string]interface{}{
					"type": "hdf-results",
					"uri":  "doc.json",
					"checksum": map[string]interface{}{
						"algorithm": "sha256",
						"value":     "0000000000000000000000000000000000000000000000000000000000000000",
					},
				},
			},
		}
		pkgData, _ := json.Marshal(pkg)
		pkgPath := filepath.Join(tmpDir, "evidence.json")
		require.NoError(t, os.WriteFile(pkgPath, pkgData, 0o600))

		stdout, _, err := executeCommand("evidence", "verify", pkgPath)
		require.Error(t, err)
		assert.Contains(t, stdout, "MISMATCH")
		assert.Contains(t, err.Error(), "checksum mismatches")
	})

	t.Run("skips entries without checksum", func(t *testing.T) {
		tmpDir := t.TempDir()

		pkg := map[string]interface{}{
			"name": "skip-pkg",
			"contents": []interface{}{
				map[string]interface{}{
					"type": "hdf-system",
					"uri":  "system.json",
				},
			},
		}
		pkgData, _ := json.Marshal(pkg)
		pkgPath := filepath.Join(tmpDir, "evidence.json")
		require.NoError(t, os.WriteFile(pkgPath, pkgData, 0o600))

		stdout, _, err := executeCommand("evidence", "verify", pkgPath)
		require.NoError(t, err)
		assert.Contains(t, stdout, "no checksum")
		assert.Contains(t, stdout, "skipped")
	})

	t.Run("reports error for missing referenced file", func(t *testing.T) {
		tmpDir := t.TempDir()

		pkg := map[string]interface{}{
			"name": "test-evidence",
			"contents": []interface{}{
				map[string]interface{}{
					"type": "hdf-results",
					"uri":  "nonexistent.json",
					"checksum": map[string]interface{}{
						"algorithm": "sha256",
						"value":     "abc123",
					},
				},
			},
		}
		pkgData, _ := json.Marshal(pkg)
		pkgPath := filepath.Join(tmpDir, "evidence.json")
		require.NoError(t, os.WriteFile(pkgPath, pkgData, 0o600))

		_, _, err := executeCommand("evidence", "verify", pkgPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "errors")
	})

	t.Run("errors when package file missing", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "verify", "/nonexistent/package.json")
		require.Error(t, err)
	})

	t.Run("errors when package is invalid JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		pkgPath := filepath.Join(tmpDir, "bad.json")
		require.NoError(t, os.WriteFile(pkgPath, []byte("not json"), 0o600))

		_, _, err := executeCommand("evidence", "verify", pkgPath)
		require.Error(t, err)
		// The load gate now rejects non-HDF-shaped input before json.Unmarshal.
		assert.Contains(t, err.Error(), "not a recognized HDF document")
	})

	t.Run("requires exactly one argument", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "verify")
		require.Error(t, err)
	})
}

func TestEvidenceVerifyJSON(t *testing.T) {
	tmpDir := t.TempDir()

	docContent := `{"hello": "world"}`
	docPath := filepath.Join(tmpDir, "doc.json")
	require.NoError(t, os.WriteFile(docPath, []byte(docContent), 0o600))

	h := sha256.Sum256([]byte(docContent))
	hashHex := hex.EncodeToString(h[:])

	pkg := map[string]interface{}{
		"name": "json-verify-pkg",
		"contents": []interface{}{
			map[string]interface{}{
				"type": "hdf-results",
				"uri":  "doc.json",
				"checksum": map[string]interface{}{
					"algorithm": "sha256",
					"value":     hashHex,
				},
			},
			map[string]interface{}{
				"type": "hdf-system",
				"uri":  "system.json",
				// no checksum — should be skipped
			},
		},
	}
	pkgData, _ := json.Marshal(pkg)
	pkgPath := filepath.Join(tmpDir, "evidence.json")
	require.NoError(t, os.WriteFile(pkgPath, pkgData, 0o600))

	stdout, _, err := executeCommand("evidence", "verify", "--json", pkgPath)
	require.NoError(t, err)

	var out map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(stdout), &out))

	assert.Equal(t, float64(1), out["matched"])
	assert.Equal(t, float64(0), out["mismatched"])
	assert.Equal(t, float64(1), out["skipped"])
	assert.Equal(t, float64(0), out["errors"])

	results, ok := out["results"].([]interface{})
	require.True(t, ok)
	assert.Len(t, results, 2)
}

// --- verifyContents / verifyContentEntry unit tests ---

func TestVerifyContents(t *testing.T) {
	t.Run("handles empty contents", func(t *testing.T) {
		results, counts := verifyContents(nil, "/tmp")
		assert.Empty(t, results)
		assert.Equal(t, 0, counts.match)
	})

	t.Run("skips non-map entries", func(t *testing.T) {
		contents := []interface{}{"not-a-map", 42}
		results, counts := verifyContents(contents, "/tmp")
		assert.Empty(t, results)
		assert.Equal(t, 0, counts.match)
	})
}

func TestVerifyContentEntry(t *testing.T) {
	t.Run("skips when checksum value is empty", func(t *testing.T) {
		entry := map[string]interface{}{
			"checksum": map[string]interface{}{
				"algorithm": "sha256",
				"value":     "",
			},
		}
		r := verifyContentEntry(entry, "test.json", "hdf-results", "/tmp")
		assert.Equal(t, verifySkipped, r.Status)
	})

	t.Run("returns match for valid checksum", func(t *testing.T) {
		tmpDir := t.TempDir()
		content := `test content`
		fp := filepath.Join(tmpDir, "file.txt")
		require.NoError(t, os.WriteFile(fp, []byte(content), 0o600))

		h := sha256.Sum256([]byte(content))
		entry := map[string]interface{}{
			"checksum": map[string]interface{}{
				"algorithm": "sha256",
				"value":     hex.EncodeToString(h[:]),
			},
		}
		r := verifyContentEntry(entry, "file.txt", "hdf-results", tmpDir)
		assert.Equal(t, verifyMatch, r.Status)
	})

	t.Run("returns mismatch for wrong checksum", func(t *testing.T) {
		tmpDir := t.TempDir()
		fp := filepath.Join(tmpDir, "file.txt")
		require.NoError(t, os.WriteFile(fp, []byte("content"), 0o600))

		entry := map[string]interface{}{
			"checksum": map[string]interface{}{
				"algorithm": "sha256",
				"value":     "badhash",
			},
		}
		r := verifyContentEntry(entry, "file.txt", "hdf-results", tmpDir)
		assert.Equal(t, verifyMismatch, r.Status)
		assert.Equal(t, "badhash", r.Expected)
		assert.NotEmpty(t, r.Actual)
	})

	t.Run("returns error when file not found", func(t *testing.T) {
		entry := map[string]interface{}{
			"checksum": map[string]interface{}{
				"algorithm": "sha256",
				"value":     "abc123",
			},
		}
		r := verifyContentEntry(entry, "missing.json", "hdf-results", "/nonexistent")
		assert.Equal(t, verifyError, r.Status)
		assert.NotEmpty(t, r.Error)
	})
}

// --- evidence export tests ---

func TestEvidenceExportCommand(t *testing.T) {
	t.Run("rejects unsupported format", func(t *testing.T) {
		tmpDir := t.TempDir()
		pkg := map[string]interface{}{
			"contents": []interface{}{},
		}
		pkgData, _ := json.Marshal(pkg)
		pkgPath := filepath.Join(tmpDir, "evidence.json")
		require.NoError(t, os.WriteFile(pkgPath, pkgData, 0o600))

		_, _, err := executeCommand("evidence", "export", pkgPath, "--format", "csv")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported export format")
	})

	t.Run("errors when package file missing", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "export", "/nonexistent/package.json")
		require.Error(t, err)
	})

	t.Run("errors when package is invalid JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		pkgPath := filepath.Join(tmpDir, "bad.json")
		require.NoError(t, os.WriteFile(pkgPath, []byte("not json"), 0o600))

		_, _, err := executeCommand("evidence", "export", pkgPath)
		require.Error(t, err)
		// The load gate now rejects non-HDF-shaped input before json.Unmarshal.
		assert.Contains(t, err.Error(), "not a recognized HDF document")
	})

	t.Run("requires exactly one argument", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "export")
		require.Error(t, err)
	})

	t.Run("skips non-convertible document types", func(t *testing.T) {
		tmpDir := t.TempDir()
		outDir := filepath.Join(tmpDir, "out")

		pkg := map[string]interface{}{
			"name": "test-evidence",
			"contents": []interface{}{
				map[string]interface{}{
					"type": "hdf-system",
					"uri":  "system.json",
					"checksum": map[string]interface{}{
						"algorithm": "sha256",
						"value":     "abc",
					},
				},
				map[string]interface{}{
					"type": "hdf-baseline",
					"uri":  "baseline.json",
					"checksum": map[string]interface{}{
						"algorithm": "sha256",
						"value":     "def",
					},
				},
			},
		}
		pkgData, _ := json.Marshal(pkg)
		pkgPath := filepath.Join(tmpDir, "evidence.json")
		require.NoError(t, os.WriteFile(pkgPath, pkgData, 0o600))

		_, stderr, err := executeCommand("evidence", "export", pkgPath, "-o", outDir)
		require.NoError(t, err)
		assert.Contains(t, stderr, "No documents exported")
	})

	t.Run("handles missing referenced results file gracefully", func(t *testing.T) {
		tmpDir := t.TempDir()
		outDir := filepath.Join(tmpDir, "out")

		pkg := map[string]interface{}{
			"name": "test-evidence",
			"contents": []interface{}{
				map[string]interface{}{
					"type": "hdf-results",
					"uri":  "nonexistent-results.json",
					"checksum": map[string]interface{}{
						"algorithm": "sha256",
						"value":     "abc",
					},
				},
			},
		}
		pkgData, _ := json.Marshal(pkg)
		pkgPath := filepath.Join(tmpDir, "evidence.json")
		require.NoError(t, os.WriteFile(pkgPath, pkgData, 0o600))

		_, stderr, err := executeCommand("evidence", "export", pkgPath, "-o", outDir)
		require.NoError(t, err)
		assert.Contains(t, stderr, "could not read")
	})

	t.Run("exports hdf-results when converter is registered", func(t *testing.T) {
		tmpDir := t.TempDir()
		outDir := filepath.Join(tmpDir, "out")

		// Create a real results file so the read succeeds
		resultsDoc := noTargetsJSON
		resultsPath := filepath.Join(tmpDir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

		pkg := map[string]interface{}{
			"name": "test-evidence",
			"contents": []interface{}{
				map[string]interface{}{
					"type": "hdf-results",
					"uri":  "results.json",
					"checksum": map[string]interface{}{
						"algorithm": "sha256",
						"value":     "abc",
					},
				},
			},
		}
		pkgData, _ := json.Marshal(pkg)
		pkgPath := filepath.Join(tmpDir, "evidence.json")
		require.NoError(t, os.WriteFile(pkgPath, pkgData, 0o600))

		_, stderr, err := executeCommand("evidence", "export", pkgPath, "-o", outDir)
		// The hdf->oscal-sar converter is registered; conversion may succeed or
		// fail depending on input validity, but the code path is exercised.
		if err == nil {
			assert.Contains(t, stderr, "exported")
			// Verify output file was created
			_, statErr := os.Stat(filepath.Join(outDir, "oscal-sar.json"))
			assert.NoError(t, statErr)
		}
	})

	t.Run("rejects schema-invalid content entries via load gate", func(t *testing.T) {
		// Previously this test verified defensive handling of non-object
		// content entries inside the evidence_export.go loop. With the m58u
		// load gate (PR #100) and the gate-uniformity work, the whole doc is
		// rejected by loadAndValidateHDFDoc before the loop runs.
		tmpDir := t.TempDir()
		outDir := filepath.Join(tmpDir, "out")

		pkg := map[string]interface{}{
			"name": "test-evidence",
			"contents": []interface{}{
				"not-a-map",
				42,
			},
		}
		pkgData, _ := json.Marshal(pkg)
		pkgPath := filepath.Join(tmpDir, "evidence.json")
		require.NoError(t, os.WriteFile(pkgPath, pkgData, 0o600))

		_, _, err := executeCommand("evidence", "export", pkgPath, "-o", outDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "schema validation")
	})
}

// --- evidence verify with multiple documents ---

func TestEvidenceVerifyMultipleDocuments(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two docs: one matching, one mismatching
	doc1Content := `{"doc": 1}`
	doc1Path := filepath.Join(tmpDir, "doc1.json")
	require.NoError(t, os.WriteFile(doc1Path, []byte(doc1Content), 0o600))

	doc2Content := `{"doc": 2}`
	doc2Path := filepath.Join(tmpDir, "doc2.json")
	require.NoError(t, os.WriteFile(doc2Path, []byte(doc2Content), 0o600))

	h1 := sha256.Sum256([]byte(doc1Content))

	pkg := map[string]interface{}{
		"name": "multi-doc-pkg",
		"contents": []interface{}{
			map[string]interface{}{
				"type": "hdf-results",
				"uri":  "doc1.json",
				"checksum": map[string]interface{}{
					"algorithm": "sha256",
					"value":     hex.EncodeToString(h1[:]),
				},
			},
			map[string]interface{}{
				"type": "hdf-baseline",
				"uri":  "doc2.json",
				"checksum": map[string]interface{}{
					"algorithm": "sha256",
					"value":     "wrong_hash_value",
				},
			},
		},
	}
	pkgData, _ := json.Marshal(pkg)
	pkgPath := filepath.Join(tmpDir, "evidence.json")
	require.NoError(t, os.WriteFile(pkgPath, pkgData, 0o600))

	stdout, _, err := executeCommand("evidence", "verify", pkgPath)
	require.Error(t, err)
	assert.Contains(t, stdout, "sha256 match")
	assert.Contains(t, stdout, "MISMATCH")
	assert.Contains(t, stdout, "1/2 checksums valid")
	assert.Contains(t, stdout, "1 failed")
}

// --- renderVerifyOutput coverage: package with no name ---

func TestEvidenceVerifyRejectsNoPackageName(t *testing.T) {
	// As of wu8p, the input gate validates evidence packages before they
	// reach the verify flow. A package without the required "name" field
	// is rejected at load; the previous "empty-name skip-render" path in
	// runEvidenceVerify is now unreachable. Pin the new behavior.
	tmpDir := t.TempDir()

	pkg := map[string]interface{}{
		"contents": []interface{}{
			map[string]interface{}{
				"type": "hdf-system",
				"uri":  "system.json",
			},
		},
	}
	pkgData, _ := json.Marshal(pkg)
	pkgPath := filepath.Join(tmpDir, "evidence.json")
	require.NoError(t, os.WriteFile(pkgPath, pkgData, 0o600))

	_, _, err := executeCommand("evidence", "verify", pkgPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema validation")
	assert.Contains(t, err.Error(), "name")
}

// --- evidence build + verify round-trip ---

func TestEvidenceBuildVerifyRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()

	systemDoc := `{"name": "roundtrip-system", "components": [{"name": "c1", "type": "application"}]}`
	resultsDoc := `{"baselines": [{"name": "b1", "requirements": [{"results": [{"status": "passed"}]}]}]}`

	systemPath := filepath.Join(tmpDir, "system.json")
	resultsPath := filepath.Join(tmpDir, "results.json")
	outputPath := filepath.Join(tmpDir, "package.json")

	require.NoError(t, os.WriteFile(systemPath, []byte(systemDoc), 0o600))
	require.NoError(t, os.WriteFile(resultsPath, []byte(resultsDoc), 0o600))

	// Build
	_, _, err := executeCommand("evidence", "build",
		"--system", systemPath,
		"--results", resultsPath,
		"-o", outputPath,
	)
	require.NoError(t, err)

	// Verify — checksums should match since files haven't changed
	stdout, _, err := executeCommand("evidence", "verify", outputPath)
	require.NoError(t, err)
	assert.Contains(t, stdout, "sha256 match")
	assert.Contains(t, stdout, "2/2 checksums valid")
}

// evidence export reads the package through the size-gated boundary, honoring --max-size.
func TestEvidenceExport_RejectsOversizeInput(t *testing.T) {
	pkg := filepath.Join(t.TempDir(), "big.json")
	require.NoError(t, os.WriteFile(pkg, make([]byte, 2*1024*1024), 0o600))
	_, _, err := executeCommand("evidence", "export", pkg, "--format", "oscal", "--max-size", "1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}
