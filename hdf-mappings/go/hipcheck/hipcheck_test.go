package hipcheck

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
)

func TestNISTControls_MultiControl(t *testing.T) {
	assert.Equal(t, []string{"SI-7", "SR-4"}, NISTControls("binary"))
	assert.Equal(t, []string{"SR-3", "SR-4"}, NISTControls("activity"))
	assert.Equal(t, []string{"SR-11", "SR-4"}, NISTControls("typo"))
}

func TestNISTControls_SingleControl(t *testing.T) {
	assert.Equal(t, []string{"SA-11"}, NISTControls("fuzz"))
	assert.Equal(t, []string{"AC-5"}, NISTControls("identity"))
	assert.Equal(t, []string{"SA-15"}, NISTControls("review"))
	assert.Equal(t, []string{"SR-6"}, NISTControls("affiliation"))
}

func TestNISTControls_StripsPublisherPrefix(t *testing.T) {
	// Hipcheck reports names as "mitre/<analysis>"; the mapping keys on the suffix.
	assert.Equal(t, []string{"SI-7", "SR-4"}, NISTControls("mitre/binary"))
	assert.Equal(t, []string{"SA-11"}, NISTControls("mitre/fuzz"))
}

func TestNISTControls_Unknown(t *testing.T) {
	assert.Nil(t, NISTControls("mitre/does-not-exist"))
	assert.Nil(t, NISTControls(""))
}

func TestExists(t *testing.T) {
	assert.True(t, Exists("entropy"))
	assert.True(t, Exists("mitre/entropy"))
	assert.False(t, Exists("nonsense"))
}

func TestAllAnalyses(t *testing.T) {
	got := AllAnalyses()
	want := []string{
		"activity", "affiliation", "binary", "churn", "entropy",
		"fuzz", "identity", "review", "typo",
	}
	assert.Equal(t, want, got)
}

func TestNISTControlsAtRev4(t *testing.T) {
	// The table is authored at Rev 5; at Rev 4 the crosswalk applies. SI-7 is
	// identical at both revisions; SR-4 (Provenance) has no Rev 4 equivalent
	// and is dropped rather than mistranslated.
	assert.Equal(t, []string{"SI-7", "SR-4"}, NISTControls("mitre/binary"))

	assert.NoError(t, nist.SetRevision(4))
	defer nist.ResetRevision()
	assert.Equal(t, []string{"SI-7"}, NISTControls("mitre/binary"))
}
