package hadolint

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookup(t *testing.T) {
	m, ok := Lookup("DL3002")
	require.True(t, ok)
	assert.Equal(t, []string{"AC-6"}, m.NIST)

	m, ok = Lookup("SC2154")
	require.True(t, ok, "shellcheck rules are in the same table")
	assert.Equal(t, []string{"SA-11"}, m.NIST)
}

func TestLookupUnknownRule(t *testing.T) {
	_, ok := Lookup("DL9999")
	assert.False(t, ok)
	_, ok = Lookup("")
	assert.False(t, ok)
	_, ok = Lookup("DL1000")
	assert.False(t, ok, "the parse-error pseudo-rule is deliberately unmapped")
}

// A lookup must never hand back the caller a slice aliasing the dataset.
func TestLookupReturnsACopy(t *testing.T) {
	m, ok := Lookup("DL3002")
	require.True(t, ok)
	m.NIST[0] = "MUTATED"
	again, _ := Lookup("DL3002")
	assert.Equal(t, []string{"AC-6"}, again.NIST)
}

func TestExists(t *testing.T) {
	assert.True(t, Exists("DL1001"))
	assert.True(t, Exists("SC1000"))
	assert.False(t, Exists("nope"))
}

func TestAllRuleIDs(t *testing.T) {
	ids := AllRuleIDs()
	assert.Len(t, ids, 105, "71 hadolint rules and 34 shellcheck rules")
	assert.True(t, sortedAscending(ids), "AllRuleIDs is sorted")
	assert.Contains(t, ids, "DL3002")
	assert.Contains(t, ids, "SC2154")

	ids[0] = "MUTATED"
	assert.NotEqual(t, "MUTATED", AllRuleIDs()[0], "AllRuleIDs returns a copy")
}

func TestGetProvenance(t *testing.T) {
	p := GetProvenance()
	assert.Equal(t, 5, p.NISTRevision)
	assert.Equal(t, "68b34a03b8746311925766da8bbb7a7490a39cb1", p.Source.Commit)
	assert.NotEmpty(t, p.Source.SHA256)
	assert.NotEmpty(t, p.Updated)
}

// The table is authored at Rev 5. SR-4 has no Rev 4 equivalent and drops to an
// empty list; a caller seeing that must use its own fallback rather than emit an
// empty nist tag.
func TestLookupForRevision_Rev4DropsSupplyChainControls(t *testing.T) {
	m, ok := LookupForRevision("DL3026", 4)
	require.True(t, ok)
	assert.Equal(t, []string{"SA-12(3)", "SA-12(15)"}, m.NIST, "SR-3 expands at Rev 4")

	m, ok = LookupForRevision("DL3055", 4)
	require.True(t, ok)
	assert.Empty(t, m.NIST, "SR-4 has no Rev 4 equivalent")

	m, ok = LookupForRevision("DL3002", 4)
	require.True(t, ok)
	assert.Equal(t, []string{"AC-6"}, m.NIST, "controls common to both revisions are unchanged")
}

func TestLookupHonorsTheProcessRevision(t *testing.T) {
	require.NoError(t, nist.SetRevision(4))
	defer nist.ResetRevision()

	m, ok := Lookup("DL3055")
	require.True(t, ok)
	assert.Empty(t, m.NIST)
}

func sortedAscending(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}
