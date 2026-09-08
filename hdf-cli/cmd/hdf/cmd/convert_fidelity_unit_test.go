package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The primary items of each document type are what a converter's declaration
// counts: requirements for results and baselines, assessments for a plan,
// overrides for amendments.
func TestCountRequirements_ByDocumentShape(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want int
	}{
		{"results across baselines", `{"baselines":[{"requirements":[{},{}]},{"requirements":[{}]}]}`, 3},
		{"baseline top-level requirements", `{"name":"b","requirements":[{},{},{},{}]}`, 4},
		{"plan assessments", `{"name":"p","assessments":[{},{}]}`, 2},
		{"amendments overrides", `{"name":"a","overrides":[{}]}`, 1},
	}
	for _, c := range cases {
		got, err := countRequirements([]byte(c.doc))
		require.NoError(t, err, c.name)
		require.Equal(t, c.want, got, c.name)
	}
}

func TestCountRequirements_RejectsUnknownShape(t *testing.T) {
	for _, doc := range []string{`{}`, `{"name":"x"}`, `[]`, `not json`} {
		_, err := countRequirements([]byte(doc))
		require.Error(t, err, doc)
	}
}
