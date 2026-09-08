package convert

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Relations declared by the converters themselves, checked through the
// registry: custom structs, dispatchers and the raw registrar.
func TestRequirementCountExpecter_CustomStructRegistrations(t *testing.T) {
	c, err := GetConverter("oscal-profile", "hdf")
	require.NoError(t, err)
	_, ok := c.(RequirementCountExpecter)
	require.True(t, ok, "oscal-profile must declare a requirement-count relation")

	// The dispatching and legacy converters declare too: the CLI counts every
	// document shape and a converter can state "no relation" for one input.
	for _, id := range []string{"oscal", "legacyhdf", "inspec"} {
		c, err := GetConverter(id, "hdf")
		require.NoError(t, err, id)
		_, ok := c.(RequirementCountExpecter)
		require.True(t, ok, "%s must declare a requirement-count relation", id)
	}
}

// Without a catalog the profile conversion is refused; the expectation must
// be refused the same way, so the CLI reports one error rather than a count.
func TestOSCALProfile_ExpectationAgreesWithConvertOnMissingCatalog(t *testing.T) {
	prev := oscalCatalogPath
	t.Cleanup(func() { SetOSCALCatalogPath(prev) })
	SetOSCALCatalogPath("")
	c, err := GetConverter("oscal-profile", "hdf")
	require.NoError(t, err)
	_, convErr := c.Convert([]byte(`{"profile":{}}`))
	_, _, expErr := c.(RequirementCountExpecter).ExpectedRequirementCount([]byte(`{"profile":{}}`))
	require.Error(t, convErr)
	require.Error(t, expErr)
	require.Equal(t, convErr.Error(), expErr.Error())
}

// The oscal auto-detect converter routes the relation the way it routes the
// conversion, and states no relation for an SSP, whose delegate emits an
// hdf-system document with nothing to count.
func TestOSCALAutoDetect_RoutesTheRelation(t *testing.T) {
	c, err := GetConverter("oscal", "hdf")
	require.NoError(t, err)
	ex, ok := c.(RequirementCountExpecter)
	require.True(t, ok)

	ssp, err := os.ReadFile(filepath.Join("..", "..", "converters", "oscal-to-hdf", "fixtures", "input", "ssp-example.json"))
	require.NoError(t, err)
	_, _, err = ex.ExpectedRequirementCount(ssp)
	require.ErrorIs(t, err, ErrNoExpectation)

	catalog, err := os.ReadFile(filepath.Join("..", "..", "converters", "oscal-to-hdf", "fixtures", "input", "catalog-moderate-resolved.json"))
	require.NoError(t, err)
	n, unit, err := ex.ExpectedRequirementCount(catalog)
	require.NoError(t, err)
	require.NotEmpty(t, unit)
	typed, err := GetConverter("oscal-catalog", "hdf")
	require.NoError(t, err)
	want, _, err := typed.(RequirementCountExpecter).ExpectedRequirementCount(catalog)
	require.NoError(t, err)
	require.Equal(t, want, n)
}

func TestRegisterRawConverter_AcceptsTheRelation(t *testing.T) {
	c, err := GetConverter("xccdf", "hdf")
	require.NoError(t, err)
	_, ok := c.(RequirementCountExpecter)
	require.True(t, ok, "xccdf auto-detect is registered through registerRawConverter with a relation")
}
