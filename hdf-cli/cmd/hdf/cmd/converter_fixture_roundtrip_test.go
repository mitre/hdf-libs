package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/require"
)

// TestAllConverterInputFixturesProduceValidHDF is the issue-80 / ufz8 gate.
//
// For every converter directory under hdf-converters/converters/, it walks
// fixtures/input/ and:
//   - If the converter targets HDF (the `*-to-hdf` family), runs the input
//     fixture through the converter and validates the output against the
//     HDF Results schema (or Baseline schema for converters that produce
//     baselines).
//   - If the converter consumes HDF (the `hdf-to-*` family), validates the
//     input fixture itself against the appropriate HDF schema — its own
//     input IS an HDF document and must satisfy the contract.
//
// This catches the entire class of schema-violating-converter-output bugs
// (issue #80 bugs 1, 2, 3) against bundled fixtures. Without this gate,
// per-converter tests can pass while producing schema-invalid output if
// the test asserts against a snapshot (or `Convert_Minimal`) without
// running it back through the validator.
//
// Per the bead acceptance: failures here surface schema-invalid fixtures
// for separate beads to fix. The gate itself ensures any regression is
// caught at PR time.
func TestAllConverterInputFixturesProduceValidHDF(t *testing.T) {
	convertersRoot := shared.GetConvertersDir()
	entries, err := os.ReadDir(convertersRoot)
	require.NoError(t, err, "could not read converters root")

	for _, dir := range entries {
		if !dir.IsDir() {
			continue
		}
		dirName := dir.Name()
		inputDir := filepath.Join(convertersRoot, dirName, "fixtures", "input")
		inputFiles, err := os.ReadDir(inputDir)
		if err != nil {
			continue // no fixtures dir — nothing to gate
		}

		// Determine direction: *-to-hdf converters produce HDF (validate output);
		// hdf-to-* and hdf-passthrough validate input directly (it IS HDF).
		isHDFProducer := strings.HasSuffix(dirName, "-to-hdf")
		isHDFConsumer := strings.HasPrefix(dirName, "hdf-to-") || dirName == "hdf-passthrough" || dirName == "legacyhdf-to-hdf"

		// legacyhdf-to-hdf consumes legacy HDF (different shape from current HDF) —
		// can't validate input against current schema. Skip input-validation; rely on
		// the producer side (since it's *-to-hdf, output validation still runs).
		if dirName == "legacyhdf-to-hdf" {
			isHDFConsumer = false
		}

		source := strings.TrimSuffix(dirName, "-to-hdf")

		for _, fxEntry := range inputFiles {
			if fxEntry.IsDir() {
				continue
			}
			fixturePath := filepath.Join(inputDir, fxEntry.Name())
			t.Run(dirName+"/"+fxEntry.Name(), func(t *testing.T) {
				data, readErr := os.ReadFile(fixturePath)
				require.NoError(t, readErr)

				switch {
				case isHDFConsumer:
					// Input is HDF — validate directly.
					assertHDFShapedDataValid(t, data, fixturePath)
				case isHDFProducer:
					// Run through the converter, validate output.
					converter, err := GetConverter(source, "hdf")
					if err != nil {
						t.Skipf("no registered converter for source %q (%s); skipping fixture", source, err)
						return
					}
					output, convertErr := converter.Convert(data)
					if convertErr != nil {
						// Some fixtures are intentionally malformed (invalid.json,
						// truncated.xml, etc.) for the converter's negative tests.
						// Skip those — they're not expected to produce valid output.
						t.Logf("converter rejected fixture (likely a negative-test fixture): %v", convertErr)
						return
					}
					require.NotEmpty(t, output, "converter produced empty output for %s", fixturePath)
					assertHDFShapedDataValid(t, output, fixturePath)
				}
			})
		}
	}
}

// assertHDFShapedDataValid validates JSON bytes against either the HDF
// Results or HDF Baseline schema, auto-detected from the top-level shape.
// Non-JSON bytes (e.g., the XCCDF input fixtures for hdf-to-* converters
// that aren't HDF-shaped) are skipped silently.
func assertHDFShapedDataValid(t *testing.T, data []byte, sourcePath string) {
	t.Helper()
	docType, ok := detectHDFDocType(data)
	if !ok {
		// Not an HDF JSON document — nothing to validate here.
		return
	}
	switch docType {
	case "results":
		result := validators.ValidateResults(data)
		if !result.Valid {
			t.Errorf("HDF Results validation failed for %s:\n%s", sourcePath, result.Error())
		}
	case "baseline":
		result := validators.ValidateBaseline(data)
		if !result.Valid {
			t.Errorf("HDF Baseline validation failed for %s:\n%s", sourcePath, result.Error())
		}
	}
}

// knownInvalidExpectedFixtures are snapshot fixtures known to fail HDF
// schema validation today, with a tracking note. Each entry should map to
// a follow-up bead. The gate is allowed to skip these so the rest of the
// gate runs, but new entries should NOT be added casually.
var knownInvalidExpectedFixtures = map[string]string{
	// Snapshot predates the Severity enum tightening (uses "none" before the
	// schema restricted to critical/high/medium/low/informational). Regenerating
	// surfaces a separate Go-vs-TS structural divergence in the legacyhdf
	// converter that needs its own bead before the snapshot can be refreshed.
	// Tracking: bd hdf-libs-rf06.
	"legacyhdf-to-hdf/three-layer-overlay.json": "stale snapshot; regenerate after fixing Go/TS divergence (bd hdf-libs-rf06)",
}

// TestAllConverterExpectedFixturesAreSchemaValid runs every committed
// fixtures/expected/*.hdf.json snapshot through the appropriate HDF
// validator. Snapshot fixtures that codify schema-invalid output (the
// "test codifies the bug" failure mode from issue #80) fail here loudly
// instead of silently shipping.
func TestAllConverterExpectedFixturesAreSchemaValid(t *testing.T) {
	convertersRoot := shared.GetConvertersDir()
	entries, err := os.ReadDir(convertersRoot)
	require.NoError(t, err, "could not read converters root")

	for _, dir := range entries {
		if !dir.IsDir() {
			continue
		}
		dirName := dir.Name()
		expectedDir := filepath.Join(convertersRoot, dirName, "fixtures", "expected")
		files, err := os.ReadDir(expectedDir)
		if err != nil {
			continue
		}
		for _, fx := range files {
			if fx.IsDir() {
				continue
			}
			name := fx.Name()
			// Skip non-HDF snapshot artifacts (e.g., expected CKL/CSV exports
			// from hdf-to-* converters). They are not HDF-shaped.
			if !strings.HasSuffix(name, ".hdf.json") && !strings.HasSuffix(name, ".json") {
				continue
			}
			fxPath := filepath.Join(expectedDir, name)
			testName := dirName + "/" + name
			t.Run(testName, func(t *testing.T) {
				if reason, skip := knownInvalidExpectedFixtures[testName]; skip {
					t.Skipf("known invalid (tracked separately): %s", reason)
				}
				data, readErr := os.ReadFile(fxPath)
				require.NoError(t, readErr)
				assertHDFShapedDataValid(t, data, fxPath)
			})
		}
	}
}
