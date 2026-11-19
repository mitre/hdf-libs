package shared

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
)

func TestRefURLsKeepsOrderAndSkipsReferencesWithoutURL(t *testing.T) {
	first, second := "https://cwe.mitre.org/data/definitions/242.html", "https://example.test/rule"
	refs := []hdf.Reference{{URL: &first}, {}, {URL: &second}}
	assert.Equal(t, []string{first, second}, RefURLs(refs))
	assert.Equal(t, []string{}, RefURLs(nil))
}
