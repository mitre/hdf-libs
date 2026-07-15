// Package shared provides shared utilities and differential testing for Go converters.
// Uses same fixtures as TypeScript tests.
package shared

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// getSharedDir returns the path to the shared/ directory.
func getSharedDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filename)
}

// GetConvertersDir returns the path to the converters/ directory.
func GetConvertersDir() string {
	return filepath.Join(getSharedDir(), "..", "..", "converters")
}

// GetBOMFixturesDir returns the path to the shared/bom-fixtures/ directory
// (real BOM documents consumed by the shared bom parser tests and by hdf-cli
// system-create tests).
func GetBOMFixturesDir() string {
	return filepath.Join(getSharedDir(), "..", "bom-fixtures")
}

// GetOutputDir returns the path to test output directory.
func GetOutputDir() string {
	return filepath.Join(getSharedDir(), "..", "..", "test-output")
}

// DifferentialTest represents a test case with input and expected output.
type DifferentialTest struct {
	Name          string
	ConverterName string
	InputFile     string
	ExpectedFile  string
}

// GetDifferentialTests loads all test cases for a converter.
func GetDifferentialTests(t *testing.T, converterName string) []DifferentialTest {
	convertersDir := GetConvertersDir()
	inputDir := filepath.Join(convertersDir, converterName, "fixtures", "input")
	expectedDir := filepath.Join(convertersDir, converterName, "fixtures", "expected")

	entries, err := os.ReadDir(inputDir)
	require.NoError(t, err, "Failed to read input directory: %s", inputDir)

	var tests []DifferentialTest
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		tests = append(tests, DifferentialTest{
			Name:          entry.Name(),
			ConverterName: converterName,
			InputFile:     filepath.Join(inputDir, entry.Name()),
			ExpectedFile:  filepath.Join(expectedDir, entry.Name()),
		})
	}

	require.NotEmpty(t, tests, "No test cases found for converter: %s", converterName)
	return tests
}

// WriteOutput writes converter output for comparison with TypeScript.
func WriteOutput(t *testing.T, converterName, testName string, data interface{}) {
	outputDir := filepath.Join(GetOutputDir(), converterName)
	err := os.MkdirAll(outputDir, 0755)
	require.NoError(t, err, "Failed to create output directory")

	outputFile := filepath.Join(outputDir, testName)
	jsonData, err := json.MarshalIndent(data, "", "  ")
	require.NoError(t, err, "Failed to marshal output")

	err = os.WriteFile(outputFile, jsonData, 0o600)
	require.NoError(t, err, "Failed to write output file")
}

// updateSnapshots is set via -update flag on `go test`.
// When true, RunSnapshotTests overwrites expected fixtures instead of comparing.
var updateSnapshots = false

func init() {
	// Register -update flag. Only takes effect during `go test`.
	// Usage: go test ./converters/nessus-to-hdf/go/... -update
	flag.BoolVar(&updateSnapshots, "update", false, "Update snapshot fixtures with current converter output")
}

// ConvertFn is a converter function that takes raw input and returns a result to snapshot.
type ConvertFn func(input []byte) (interface{}, error)

// RunSnapshotTests discovers expected fixtures for a converter and verifies
// that the converter produces matching output. Each fixture becomes a subtest
// named after the input file, so you can run a single fixture with:
//
//	go test -run TestSnapshots/sample.nessus
//
// To update snapshots after intentional changes:
//
//	go test -run TestSnapshots -update
func RunSnapshotTests(t *testing.T, converterName string, convertFn ConvertFn, maskStartTime ...string) {
	t.Helper()

	// syntheticStartTime lists the input-fixture names whose startTime the
	// converter synthesizes (source carries no scan time), so it must be masked;
	// the sentinel "*" masks every fixture. Fixtures NOT listed have startTime
	// asserted against the input-derived value — a masked-but-derivable startTime
	// is a hidden wrong-time bug (the u6j3 axis).
	syntheticStartTime := make(map[string]bool, len(maskStartTime))
	for _, name := range maskStartTime {
		syntheticStartTime[name] = true
	}

	convertersDir := GetConvertersDir()
	expectedDir := filepath.Join(convertersDir, converterName, "fixtures", "expected")
	inputDir := filepath.Join(convertersDir, converterName, "fixtures", "input")

	entries, err := os.ReadDir(expectedDir)
	if err != nil {
		t.Fatalf("no expected/ fixtures for %s: %v", converterName, err)
	}

	var misnamed []string
	asserted := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		// Expected file: "sample.nessus.hdf.json" → input file: "sample.nessus"
		expectedName := entry.Name()
		inputName := strings.TrimSuffix(expectedName, ".hdf.json")
		if inputName == expectedName {
			misnamed = append(misnamed, expectedName)
			continue
		}
		asserted++

		t.Run(inputName, func(t *testing.T) {
			inputPath := filepath.Join(inputDir, inputName)
			expectedPath := filepath.Join(expectedDir, expectedName)

			inputData, err := os.ReadFile(inputPath)
			require.NoError(t, err, "golden %s has no matching input fixture %s", expectedName, inputPath)

			result, err := convertFn(inputData)
			require.NoError(t, err, "Converter failed for %s", inputName)

			actualJSON, err := json.MarshalIndent(result, "", "  ")
			require.NoError(t, err, "Failed to marshal converter output")
			actualJSON = append(actualJSON, '\n')

			if updateSnapshots {
				err = os.WriteFile(expectedPath, actualJSON, 0o600)
				require.NoError(t, err, "Failed to update snapshot")
				t.Logf("Updated snapshot: %s", expectedPath)
				return
			}

			expectedJSON, err := os.ReadFile(expectedPath)
			require.NoError(t, err, "Failed to read expected fixture: %s", expectedPath)

			// timestamp (doc conversion time) is always volatile; startTime is
			// masked only for fixtures whose source carries no scan time.
			mask := map[string]bool{"timestamp": true}
			if syntheticStartTime["*"] || syntheticStartTime[inputName] {
				mask["startTime"] = true
			}
			normalizedExpected := normalizeVolatileFields(expectedJSON, mask)
			normalizedActual := normalizeVolatileFields(actualJSON, mask)

			require.JSONEq(t, string(normalizedExpected), string(normalizedActual),
				"Snapshot mismatch for %s.\nRun with -update to accept new output.", inputName)
		})
	}

	// A golden only gets asserted if it is named "<input>.hdf.json". Anything
	// else is dead weight the suite would skip in silence, leaving the test
	// green while it proves nothing — fail loudly instead.
	if len(misnamed) > 0 {
		t.Errorf("%s: golden(s) %v are not named <input>.hdf.json, so no subtest asserts them; rename them or delete them",
			converterName, misnamed)
	}
	if asserted == 0 {
		t.Fatalf("%s: snapshot suite registered zero subtests — no golden in %s matched the <input>.hdf.json convention",
			converterName, expectedDir)
	}
}

// RunSnapshotTestsRaw is like RunSnapshotTests but for converters that return
// raw bytes (e.g., XCCDF auto-detect, OSCAL auto-detect).
func RunSnapshotTestsRaw(t *testing.T, converterName string, convertFn func(input []byte) ([]byte, error), maskStartTime ...string) {
	t.Helper()
	RunSnapshotTests(t, converterName, func(input []byte) (interface{}, error) {
		output, err := convertFn(input)
		if err != nil {
			return nil, err
		}
		var parsed interface{}
		if err := json.Unmarshal(output, &parsed); err != nil {
			return nil, err
		}
		return parsed, nil
	}, maskStartTime...)
}

// normalizeVolatileFields zeroes out the keys in mask so snapshot tests are
// deterministic. Operates on raw JSON bytes.
func normalizeVolatileFields(data []byte, mask map[string]bool) []byte {
	var doc interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return data // not valid JSON, return as-is
	}
	normalizeValue(doc, mask)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return data
	}
	return out
}

// Masking discipline (kept in lockstep with shared/typescript/snapshot.ts):
//   - timestamp (the document write/conversion time) is ALWAYS masked.
//   - startTime is masked PER-FIXTURE via RunSnapshotTests' maskStartTime arg —
//     only for fixtures whose source carries no scan time. A fixture whose source
//     DOES carry a scan time asserts startTime against the input-derived value.
//   - resultsChecksum is intentionally NOT masked: it is sha256(input), fully
//     deterministic and identical across Go/TS, so asserting it catches real
//     output/checksum divergence.
func normalizeValue(v interface{}, mask map[string]bool) {
	switch val := v.(type) {
	case map[string]interface{}:
		for k, child := range val {
			if mask[k] {
				val[k] = "(normalized)"
			} else {
				normalizeValue(child, mask)
			}
		}
	case []interface{}:
		for _, item := range val {
			normalizeValue(item, mask)
		}
	}
}

// ConverterContractSpec defines the inputs for RunConverterContractTests.
type ConverterContractSpec struct {
	// ConverterName is the directory name under converters/ (e.g. "gosec-to-hdf").
	ConverterName string
	// ConvertFn is the converter function to test.
	ConvertFn ConvertFn
	// MinimalFixture is the path relative to fixtures/input/ (e.g. "minimal.json").
	MinimalFixture string
	// InvalidInput is the bytes to use for the invalid input test.
	// Defaults to "not valid json" if empty.
	InvalidInput string
}

// RunConverterContractTests runs universal converter contract tests:
// empty input fails, invalid input fails, minimal fixture converts
// without error. Call this alongside RunSnapshotTests to cover both
// the contract and the output correctness.
func RunConverterContractTests(t *testing.T, spec ConverterContractSpec) {
	t.Helper()

	t.Run("rejects empty input", func(t *testing.T) {
		_, err := spec.ConvertFn([]byte(""))
		require.Error(t, err, "empty input should produce an error")
	})

	t.Run("rejects invalid input", func(t *testing.T) {
		invalid := spec.InvalidInput
		if invalid == "" {
			invalid = "not valid json"
		}
		_, err := spec.ConvertFn([]byte(invalid))
		require.Error(t, err, "invalid input should produce an error")
	})

	t.Run("converts minimal fixture", func(t *testing.T) {
		inputPath := filepath.Join(GetConvertersDir(), spec.ConverterName, "fixtures", "input", spec.MinimalFixture)
		data, err := os.ReadFile(inputPath)
		if err != nil {
			t.Skipf("Fixture not found: %s", inputPath)
			return
		}

		result, err := spec.ConvertFn(data)
		require.NoError(t, err, "minimal fixture should convert without error")
		require.NotNil(t, result, "converter output should not be nil")
	})
}

// LoadJSON loads and unmarshals a JSON file.
func LoadJSON(t *testing.T, path string, v interface{}) {
	data, err := os.ReadFile(path)
	require.NoError(t, err, "Failed to read file: %s", path)

	err = json.Unmarshal(data, v)
	require.NoError(t, err, "Failed to unmarshal JSON: %s", path)
}

// CompareJSON compares two JSON structures.
func CompareJSON(t *testing.T, expected, actual interface{}, msgAndArgs ...interface{}) {
	expectedJSON, err := json.MarshalIndent(expected, "", "  ")
	require.NoError(t, err, "Failed to marshal expected")

	actualJSON, err := json.MarshalIndent(actual, "", "  ")
	require.NoError(t, err, "Failed to marshal actual")

	require.JSONEq(t, string(expectedJSON), string(actualJSON), msgAndArgs...)
}
