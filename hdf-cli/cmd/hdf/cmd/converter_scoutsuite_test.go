package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestScoutSuiteConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "scoutsuite",
		DisplayName:    "ScoutSuite to HDF",
		FixtureDir:     "scoutsuite-to-hdf",
		MinimalFixture: "input/scoutsuite_sample.js",
		ErrPrefix:      "scoutsuite conversion failed",
		InvalidInput:   "not valid json",
	})
}

func TestScoutSuiteConverter_AutoDetect(t *testing.T) {
	fixture := converterFixturePath(t, "scoutsuite-to-hdf", "input/scoutsuite_sample.js")
	outputPath := filepath.Join(t.TempDir(), "out.json")

	_, stderr, err := executeCommand("convert", fixture, "-o", outputPath)
	if err != nil {
		t.Fatalf("auto-detect convert failed: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stderr, "ScoutSuite") {
		t.Errorf("expected stderr to confirm ScoutSuite detection; got: %s", stderr)
	}
}
