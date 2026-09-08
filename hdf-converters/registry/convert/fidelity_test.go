package convert

import (
	"testing"

	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func noopResults(_ []byte, _ string) (*hdf.HDFResults, error) { return &hdf.HDFResults{}, nil }

func TestWithExpectedRequirementCount_DeclaresTheInterface(t *testing.T) {
	t.Cleanup(func() {
		UnregisterConverter("fidelity-test-declared", "hdf")
		UnregisterConverter("fidelity-test-plain", "hdf")
	})
	registerHDFConverter("fidelity-test-declared", "Declared", "declared", noopResults,
		WithExpectedRequirementCount(func(in []byte) (int, string, error) { return len(in), "bytes", nil }))
	registerHDFConverter("fidelity-test-plain", "Plain", "plain", noopResults)

	declared, err := GetConverter("fidelity-test-declared", "hdf")
	require.NoError(t, err)
	ex, ok := declared.(RequirementCountExpecter)
	require.True(t, ok, "a converter registered with WithExpectedRequirementCount must declare the interface")
	n, unit, err := ex.ExpectedRequirementCount([]byte("abc"))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, "bytes", unit)

	plain, err := GetConverter("fidelity-test-plain", "hdf")
	require.NoError(t, err)
	_, ok = plain.(RequirementCountExpecter)
	require.False(t, ok, "a converter without a declared relation must NOT be checked")
}

func TestWithExpectedRequirementCount_KeepsOtherOptions(t *testing.T) {
	t.Cleanup(func() { UnregisterConverter("fidelity-test-both", "hdf") })
	registerHDFConverter("fidelity-test-both", "Both", "both", noopResults,
		WithEmptyInputOK(),
		WithExpectedRequirementCount(func([]byte) (int, string, error) { return 1, "unit", nil }))
	both, err := GetConverter("fidelity-test-both", "hdf")
	require.NoError(t, err)
	e, ok := both.(EmptyInputAccepting)
	require.True(t, ok)
	require.True(t, e.AcceptsEmptyInput())
	_, ok = both.(RequirementCountExpecter)
	require.True(t, ok)
	require.Equal(t, "Both", both.Name())
}
