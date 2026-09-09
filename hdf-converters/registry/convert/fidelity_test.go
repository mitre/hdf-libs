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

func noopBaseline(_ []byte, _ string) (*hdf.HDFBaseline, error)     { return &hdf.HDFBaseline{}, nil }
func noopPlan(_ []byte, _ string) (*hdf.HDFPlan, error)             { return &hdf.HDFPlan{}, nil }
func noopAmendments(_ []byte, _ string) (*hdf.HDFAmendments, error) { return &hdf.HDFAmendments{}, nil }

// The baseline, plan and amendments register helpers must honor the option the
// same way the results helper does: declared converters expose the interface
// with their display name intact, undeclared ones stay unchecked.
func TestWithExpectedRequirementCount_TypedRegisterHelpers(t *testing.T) {
	relation := WithExpectedRequirementCount(func(in []byte) (int, string, error) { return len(in), "bytes", nil })
	cases := []struct {
		kind     string
		register func(source, name string, opts ...ConverterOption)
	}{
		{"baseline", func(source, name string, opts ...ConverterOption) {
			registerHDFBaselineConverter(source, name, source, noopBaseline, opts...)
		}},
		{"plan", func(source, name string, opts ...ConverterOption) {
			registerHDFPlanConverter(source, name, source, noopPlan, opts...)
		}},
		{"amendments", func(source, name string, opts ...ConverterOption) {
			registerHDFAmendmentsConverter(source, name, source, noopAmendments, opts...)
		}},
	}
	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			declaredID, plainID := "fidelity-test-"+c.kind+"-declared", "fidelity-test-"+c.kind+"-plain"
			t.Cleanup(func() {
				UnregisterConverter(declaredID, "hdf")
				UnregisterConverter(plainID, "hdf")
			})
			c.register(declaredID, "Declared "+c.kind, relation)
			c.register(plainID, "Plain "+c.kind)

			declared, err := GetConverter(declaredID, "hdf")
			require.NoError(t, err)
			ex, ok := declared.(RequirementCountExpecter)
			require.True(t, ok, "a %s converter registered with WithExpectedRequirementCount must declare the interface", c.kind)
			n, unit, err := ex.ExpectedRequirementCount([]byte("abcd"))
			require.NoError(t, err)
			require.Equal(t, 4, n)
			require.Equal(t, "bytes", unit)
			require.Equal(t, "Declared "+c.kind, declared.Name())
			out, err := declared.Convert([]byte("{}"))
			require.NoError(t, err)
			require.NotEmpty(t, out, "the wrapper must still convert through the embedded converter")

			plain, err := GetConverter(plainID, "hdf")
			require.NoError(t, err)
			_, ok = plain.(RequirementCountExpecter)
			require.False(t, ok, "a %s converter without a declared relation must NOT be checked", c.kind)
			require.Equal(t, "Plain "+c.kind, plain.Name())
		})
	}
}
