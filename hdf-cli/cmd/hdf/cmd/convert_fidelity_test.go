package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	convreg "github.com/mitre/hdf-libs/hdf-converters/v3/registry/convert"
)

// fidelityFake converts like the real SARIF converter but declares whatever
// requirement count the test says, so the CLI's check can be exercised
// without depending on any converter's own relation.
type fidelityFake struct {
	inner  Converter
	expect int
	unit   string
}

func (f *fidelityFake) Name() string                      { return "Fidelity fake" }
func (f *fidelityFake) Convert(in []byte) ([]byte, error) { return f.inner.Convert(in) }
func (f *fidelityFake) ExpectedRequirementCount([]byte) (int, string, error) {
	return f.expect, f.unit, nil
}

func registerFidelityFake(t *testing.T, name string, expect int) string {
	t.Helper()
	inner, err := GetConverter("sarif", "hdf")
	require.NoError(t, err)
	RegisterConverter(name, "hdf", &fidelityFake{inner: inner, expect: expect, unit: "fake findings"})
	t.Cleanup(func() { UnregisterConverter(name, "hdf") })
	// empty-results.sarif converts to exactly one (no-findings) requirement.
	return converterFixturePath(t, "sarif-to-hdf", "input/empty-results.sarif")
}

func TestConvertCommand_FidelityMismatchFailsAndWritesNothing(t *testing.T) {
	fixture := registerFidelityFake(t, "fidelity-fake-mismatch", 99)
	out := filepath.Join(t.TempDir(), "out.hdf.json")

	_, stderr, err := executeCommand("convert", "--from", "fidelity-fake-mismatch", "--to", "hdf", fixture, "-o", out)
	require.Error(t, err, "a conversion whose requirement count does not match the declaration must fail")
	msg := err.Error() + "\n" + stderr
	require.Contains(t, msg, "99")
	require.Contains(t, msg, "produced 1")
	require.Contains(t, msg, "fake findings")
	_, statErr := os.Stat(out)
	require.True(t, os.IsNotExist(statErr), "no output may be written for a conversion that lost findings")
}

func TestConvertCommand_FidelityMatchReportsTheRelation(t *testing.T) {
	fixture := registerFidelityFake(t, "fidelity-fake-match", 1)
	out := filepath.Join(t.TempDir(), "out.hdf.json")

	_, stderr, err := executeCommand("convert", "--from", "fidelity-fake-match", "--to", "hdf", fixture, "-o", out)
	require.NoError(t, err, "stderr: %s", stderr)
	require.Contains(t, stderr, "1 requirement")
	require.Contains(t, stderr, "fake findings")
	_, statErr := os.Stat(out)
	require.NoError(t, statErr)
}

func TestConvertCommand_FidelityIsCheckedInBulk(t *testing.T) {
	fixture := registerFidelityFake(t, "fidelity-fake-bulk", 99)
	second := converterFixturePath(t, "sarif-to-hdf", "input/gosec.sarif")
	outDir := t.TempDir()

	_, stderr, err := executeCommand("convert", "--from", "fidelity-fake-bulk", "--to", "hdf", fixture, second, "-o", outDir)
	require.Error(t, err)
	require.Contains(t, err.Error()+"\n"+stderr, "produced")
	entries, readErr := os.ReadDir(outDir)
	require.NoError(t, readErr)
	require.Empty(t, entries, "bulk convert must not write a document that lost findings")
}

// A downgrade to a legacy output version rewrites the document into the
// profiles shape after conversion. The declaration is about what the
// converter produced, so the check must run before that post-processing.
func TestConvertCommand_FidelityRunsBeforeVersionDowngrade(t *testing.T) {
	fixture := registerFidelityFake(t, "fidelity-fake-downgrade", 1)
	out := filepath.Join(t.TempDir(), "out.json")

	_, stderr, err := executeCommand("convert", "--from", "fidelity-fake-downgrade", "--to", "hdf@2", fixture, "-o", out)
	require.NoError(t, err, "stderr: %s", stderr)
	require.Contains(t, stderr, "1 requirement")
}

// noRelationFake converts but declines to state a relation for its input,
// the way a dispatching converter does when its delegate emits a document
// with no primary items. The conversion must proceed unchecked, not fail.
type noRelationFake struct{ inner Converter }

func (f *noRelationFake) Name() string                      { return "No-relation fake" }
func (f *noRelationFake) Convert(in []byte) ([]byte, error) { return f.inner.Convert(in) }
func (f *noRelationFake) ExpectedRequirementCount([]byte) (int, string, error) {
	return 0, "", convreg.ErrNoExpectation
}

func TestConvertCommand_FidelitySkippedWhenConverterStatesNoRelation(t *testing.T) {
	inner, err := GetConverter("sarif", "hdf")
	require.NoError(t, err)
	RegisterConverter("fidelity-fake-norelation", "hdf", &noRelationFake{inner: inner})
	t.Cleanup(func() { UnregisterConverter("fidelity-fake-norelation", "hdf") })
	fixture := converterFixturePath(t, "sarif-to-hdf", "input/empty-results.sarif")
	out := filepath.Join(t.TempDir(), "out.json")

	_, stderr, err := executeCommand("convert", "--from", "fidelity-fake-norelation", "--to", "hdf", fixture, "-o", out)
	require.NoError(t, err, "stderr: %s", stderr)
	require.NotContains(t, stderr, "matching the input")
	_, statErr := os.Stat(out)
	require.NoError(t, statErr)
}

// Bulk mode captures each file's stderr and prints one line per file, so
// the relation has to travel on that line or the pipeline log never sees it.
func TestConvertCommand_BulkOkLineCarriesTheRelation(t *testing.T) {
	fixture := registerFidelityFake(t, "fidelity-fake-bulk-ok", 1)
	outDir := t.TempDir()

	_, stderr, err := executeCommand("convert", "--from", "fidelity-fake-bulk-ok", "--to", "hdf", fixture, fixture, "-o", outDir)
	require.NoError(t, err, "stderr: %s", stderr)
	require.Contains(t, stderr, "ok (1 requirement, matching the input's fake findings)")
}
