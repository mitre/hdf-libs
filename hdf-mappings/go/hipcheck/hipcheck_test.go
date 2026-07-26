package hipcheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
