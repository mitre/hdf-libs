package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
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
