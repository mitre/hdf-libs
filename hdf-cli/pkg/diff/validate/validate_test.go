package validate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	engine "github.com/mitre/hdf-cli/pkg/diff/engine"
	"github.com/mitre/hdf-cli/pkg/diff/normalize"
	types "github.com/mitre/hdf-cli/pkg/diff/types"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fixture helpers (same pattern as engine/differential_test.go).

// fixturesDir returns the absolute path to the shared test fixtures directory.
func fixturesDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// From hdf-cli/pkg/diff/validate/ up to hdf-libs root, then into hdf-diff/test/fixtures.
	dir := filepath.Join(filepath.Dir(filename), "..", "..", "..", "..", "hdf-diff", "test", "fixtures")
	absDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("filepath.Abs failed: %v", err)
	}
	return absDir
}

// loadV2Fixture loads a v2-format HDF JSON fixture into hdf.HdfResults.
func loadV2Fixture(t *testing.T, name string) hdf.HdfResults {
	t.Helper()
	path := filepath.Join(fixturesDir(t), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture %s not found: %v (run from monorepo root)", name, err)
	}
	result, err := hdf.UnmarshalHdfResults(data)
	if err != nil {
		t.Fatalf("failed to parse v2 fixture %s: %v", name, err)
	}
	return result
}

// loadV1Fixture loads a v1-format InSpec exec-json fixture, normalizes it to v2,
// and returns hdf.HdfResults.
func loadV1Fixture(t *testing.T, name string) hdf.HdfResults {
	t.Helper()
	path := filepath.Join(fixturesDir(t), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture %s not found: %v (run from monorepo root)", name, err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to parse JSON for %s: %v", name, err)
	}
	if !normalize.IsV1Format(raw) {
		t.Fatalf("expected %s to be v1 format", name)
	}
	result, _, err := normalize.ToV2(data)
	if err != nil {
		t.Fatalf("failed to normalize v1 fixture %s: %v", name, err)
	}
	return result
}

// runDiff runs the diff engine on two HDF results documents with default options.
func runDiff(t *testing.T, oldDoc, newDoc hdf.HdfResults) types.HdfComparison {
	t.Helper()
	comp, err := engine.DiffHdf(oldDoc, []hdf.HdfResults{newDoc}, engine.Options{})
	require.NoError(t, err, "DiffHdf should not return an error")
	return comp
}

// comparisonToAny marshals an HdfComparison to JSON and back to any (map),
// which is the format the validator expects.
//
// Note: ValidateComparison now calls NormalizeForSchema internally,
// so this helper no longer needs to normalize manually. It just
// marshals the Go struct to a generic map[string]any for the validator.
func comparisonToAny(t *testing.T, comp types.HdfComparison) any {
	t.Helper()
	data, err := json.Marshal(comp)
	require.NoError(t, err, "json.Marshal should not fail")
	var doc any
	err = json.Unmarshal(data, &doc)
	require.NoError(t, err, "json.Unmarshal should not fail")
	return doc
}

// Test 1: Valid output from DiffHdf validates successfully.
func TestValidateComparison_DiffOutput(t *testing.T) {
	scanBefore := loadV2Fixture(t, "scan-before.json")
	scanAfter := loadV2Fixture(t, "scan-after.json")
	comp := runDiff(t, scanBefore, scanAfter)
	doc := comparisonToAny(t, comp)

	result := ValidateComparison(doc)
	if !result.Valid {
		t.Logf("Validation errors: %v", result.Errors)
	}
	assert.True(t, result.Valid, "DiffHdf output should validate against schema")
	assert.Empty(t, result.Errors, "No errors expected for valid output")
}

// Test 2: Valid identical comparison validates.
func TestValidateComparison_Identical(t *testing.T) {
	scanBefore := loadV2Fixture(t, "scan-before.json")
	comp := runDiff(t, scanBefore, scanBefore)
	doc := comparisonToAny(t, comp)

	result := ValidateComparison(doc)
	if !result.Valid {
		t.Logf("Validation errors: %v", result.Errors)
	}
	assert.True(t, result.Valid, "identical comparison should validate")
}

// Test 3: Valid fleet comparison validates.
func TestValidateComparison_Fleet(t *testing.T) {
	scanBefore := loadV2Fixture(t, "scan-before.json")
	scanAfter := loadV2Fixture(t, "scan-after.json")

	comp, err := engine.DiffHdf(scanBefore, []hdf.HdfResults{scanAfter, scanBefore}, engine.Options{
		ComparisonMode: types.ModeFleet,
	})
	require.NoError(t, err)
	doc := comparisonToAny(t, comp)

	result := ValidateComparison(doc)
	if !result.Valid {
		t.Logf("Validation errors: %v", result.Errors)
	}
	assert.True(t, result.Valid, "fleet mode comparison should validate")
}

// Test 4: Invalid document rejected (missing required fields).
func TestValidateComparison_InvalidDocument(t *testing.T) {
	doc := map[string]any{"foo": "bar"}
	result := ValidateComparison(doc)

	assert.False(t, result.Valid, "invalid document should be rejected")
	assert.NotEmpty(t, result.Errors, "errors should be present")
	assert.Greater(t, len(result.Errors), 0, "at least one error expected")
}

// Test 5: Missing formatVersion rejected.
func TestValidateComparison_MissingFormatVersion(t *testing.T) {
	doc := map[string]any{"formatVersion": "1.0.0"}
	result := ValidateComparison(doc)

	assert.False(t, result.Valid, "document with only formatVersion should be rejected")
	assert.NotEmpty(t, result.Errors, "errors should be present for missing required fields")
}

// Test 6: Invalid comparisonMode rejected.
func TestValidateComparison_InvalidComparisonMode(t *testing.T) {
	scanBefore := loadV2Fixture(t, "scan-before.json")
	scanAfter := loadV2Fixture(t, "scan-after.json")
	comp := runDiff(t, scanBefore, scanAfter)
	doc := comparisonToAny(t, comp)

	// Modify to invalid comparison mode.
	docMap := doc.(map[string]any)
	docMap["formatVersion"] = "2.0.0"
	result := ValidateComparison(docMap)

	assert.False(t, result.Valid, "document with invalid formatVersion should be rejected")
}

// Test 7: Nginx v1 comparison validates.
func TestValidateComparison_NginxV1(t *testing.T) {
	nginxFailing := loadV1Fixture(t, "nginx-failing.json")
	nginxClean := loadV1Fixture(t, "nginx-clean.json")
	comp := runDiff(t, nginxFailing, nginxClean)
	doc := comparisonToAny(t, comp)

	result := ValidateComparison(doc)
	if !result.Valid {
		errCount := len(result.Errors)
		if errCount > 5 {
			errCount = 5
		}
		t.Logf("Validation errors (first %d): %v", errCount, result.Errors[:errCount])
	}
	assert.True(t, result.Valid, "nginx (failing -> clean) comparison should validate")
}

// Test 8: Ubuntu comparison validates.
func TestValidateComparison_UbuntuV1(t *testing.T) {
	vanilla := loadV1Fixture(t, "ubuntu-22-vanilla.json")
	hardened := loadV1Fixture(t, "ubuntu-22-hardened.json")
	comp := runDiff(t, vanilla, hardened)
	doc := comparisonToAny(t, comp)

	result := ValidateComparison(doc)
	if !result.Valid {
		errCount := len(result.Errors)
		if errCount > 5 {
			errCount = 5
		}
		t.Logf("Validation errors (first %d): %v", errCount, result.Errors[:errCount])
	}
	assert.True(t, result.Valid, "ubuntu (vanilla -> hardened) comparison should validate")
}

// Test 9: Empty object rejected.
func TestValidateComparison_EmptyObject(t *testing.T) {
	doc := map[string]any{}
	result := ValidateComparison(doc)

	assert.False(t, result.Valid, "empty object should be rejected")
	assert.NotEmpty(t, result.Errors, "errors should be present for empty object")
}

// Test 10: Error messages are descriptive strings.
func TestValidateComparison_DescriptiveErrors(t *testing.T) {
	doc := map[string]any{"foo": "bar"}
	result := ValidateComparison(doc)

	require.False(t, result.Valid)
	require.NotEmpty(t, result.Errors)

	for _, errMsg := range result.Errors {
		assert.IsType(t, "", errMsg, "each error should be a string")
		assert.NotEmpty(t, errMsg, "error messages should not be empty")
		// Error messages should contain meaningful information.
		assert.Greater(t, len(errMsg), 5, "error messages should be descriptive (more than 5 chars)")
	}
}
