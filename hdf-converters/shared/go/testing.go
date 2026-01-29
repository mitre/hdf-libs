// Package testing provides differential testing utilities for Go converters.
// Uses same fixtures as TypeScript tests.
package testing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// getSharedDir returns the path to the shared/ directory
func getSharedDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filename)
}

// GetConvertersDir returns the path to the converters/ directory
func GetConvertersDir() string {
	return filepath.Join(getSharedDir(), "..", "..", "converters")
}

// GetOutputDir returns the path to test output directory
func GetOutputDir() string {
	return filepath.Join(getSharedDir(), "..", "..", "test-output")
}

// DifferentialTest represents a test case with input and expected output
type DifferentialTest struct {
	Name          string
	ConverterName string
	InputFile     string
	ExpectedFile  string
}

// GetDifferentialTests loads all test cases for a converter
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

// WriteOutput writes converter output for comparison with TypeScript
func WriteOutput(t *testing.T, converterName, testName string, data interface{}) {
	outputDir := filepath.Join(GetOutputDir(), converterName)
	err := os.MkdirAll(outputDir, 0755)
	require.NoError(t, err, "Failed to create output directory")

	outputFile := filepath.Join(outputDir, testName)
	jsonData, err := json.MarshalIndent(data, "", "  ")
	require.NoError(t, err, "Failed to marshal output")

	err = os.WriteFile(outputFile, jsonData, 0644)
	require.NoError(t, err, "Failed to write output file")
}

// LoadJSON loads and unmarshals a JSON file
func LoadJSON(t *testing.T, path string, v interface{}) {
	data, err := os.ReadFile(path)
	require.NoError(t, err, "Failed to read file: %s", path)

	err = json.Unmarshal(data, v)
	require.NoError(t, err, "Failed to unmarshal JSON: %s", path)
}

// CompareJSON compares two JSON structures
func CompareJSON(t *testing.T, expected, actual interface{}, msgAndArgs ...interface{}) {
	expectedJSON, err := json.MarshalIndent(expected, "", "  ")
	require.NoError(t, err, "Failed to marshal expected")

	actualJSON, err := json.MarshalIndent(actual, "", "  ")
	require.NoError(t, err, "Failed to marshal actual")

	require.JSONEq(t, string(expectedJSON), string(actualJSON), msgAndArgs...)
}
