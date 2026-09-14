package checkov

import (
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
)

func TestLookup_MappedCheck(t *testing.T) {
	m, ok := Lookup("CKV_AWS_18")
	require.True(t, ok)
	assert.Equal(t, []string{"CCI-000130", "CCI-000169"}, m.CCI)
	assert.Equal(t, []string{"AU-2", "AU-12"}, m.NIST)
}

func TestLookup_PreservesSourceOrder(t *testing.T) {
	m, ok := Lookup("CKV_AWS_145")
	require.True(t, ok)
	assert.Equal(t, []string{"CCI-002476", "CCI-002451"}, m.CCI)
	assert.Equal(t, []string{"SC-28(1)", "SC-12(1)"}, m.NIST)
}

func TestLookup_Unmapped(t *testing.T) {
	_, ok := Lookup("CKV_DOES_NOT_EXIST")
	assert.False(t, ok)
	_, ok = Lookup("")
	assert.False(t, ok)
}

func TestLookup_ReturnsCopies(t *testing.T) {
	m, ok := Lookup("CKV_AWS_18")
	require.True(t, ok)
	m.CCI[0] = "mutated"
	m.NIST[0] = "mutated"

	again, _ := Lookup("CKV_AWS_18")
	assert.Equal(t, []string{"CCI-000130", "CCI-000169"}, again.CCI)
	assert.Equal(t, []string{"AU-2", "AU-12"}, again.NIST)
}

func TestLookup_TranslatesToCurrentRevision(t *testing.T) {
	// SR-3 is Rev 5 only; the crosswalk redirects it to its Rev 4 origins.
	// CCIs are revision-independent identifiers and pass through unchanged.
	m, ok := Lookup("CKV_TF_1")
	require.True(t, ok)
	assert.Equal(t, []string{"SI-7(6)", "SR-3"}, m.NIST)

	require.NoError(t, nist.SetRevision(4))
	defer nist.ResetRevision()
	m4, ok := Lookup("CKV_TF_1")
	require.True(t, ok)
	assert.Equal(t, []string{"SI-7(6)", "SA-12(3)", "SA-12(15)"}, m4.NIST)
	assert.Equal(t, []string{"CCI-002705", "CCI-003610"}, m4.CCI)
}

func TestExists(t *testing.T) {
	assert.True(t, Exists("CKV2_AWS_6"))
	assert.False(t, Exists("CKV_DOES_NOT_EXIST"))
}

func TestAllCheckIDs(t *testing.T) {
	ids := AllCheckIDs()
	assert.Len(t, ids, 1341)
	assert.True(t, sort.StringsAreSorted(ids))
	assert.Equal(t, "CKV2_ADO_1", ids[0])
}

func TestDatasetEntriesAreWellFormed(t *testing.T) {
	cciPattern := regexp.MustCompile(`^CCI-\d{6}$`)
	for _, id := range AllCheckIDs() {
		m, ok := LookupForRevision(id, 5)
		require.True(t, ok, id)
		assert.NotEmpty(t, m.CCI, "%s has no CCI", id)
		assert.NotEmpty(t, m.NIST, "%s has no NIST control", id)
		for _, c := range m.CCI {
			assert.Regexp(t, cciPattern, c, "%s carries a malformed CCI", id)
		}
	}
}

func TestProvenance(t *testing.T) {
	p := GetProvenance()
	assert.Equal(t, "3.2.506", p.CheckovVersion)
	assert.Equal(t, 5, p.NISTRevision)
	assert.Equal(t, "@mitre/hdf-converters", p.Source.Package)
	assert.Equal(t, "2.14.0", p.Source.Version)
}
