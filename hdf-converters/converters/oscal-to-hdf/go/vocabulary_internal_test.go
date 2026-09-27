package oscal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVocabulary_RejectsMalformedTables(t *testing.T) {
	row := VocabularyRow{Name: "a"}
	for _, tc := range []struct {
		name  string
		table vocabularyTable
		want  string
	}{
		{"no namespace", vocabularyTable{DefaultNamespace: "d", Props: []VocabularyRow{row}}, "oscal: the OSCAL vocabulary table has no namespace"},
		{"no default namespace", vocabularyTable{Namespace: "n", Props: []VocabularyRow{row}}, "oscal: the OSCAL vocabulary table has no defaultNamespace"},
		{"no rows", vocabularyTable{Namespace: "n", DefaultNamespace: "d"}, "oscal: the OSCAL vocabulary table has no rows"},
		{"duplicate row", vocabularyTable{Namespace: "n", DefaultNamespace: "d", Props: []VocabularyRow{row, row}}, `oscal: the OSCAL vocabulary table defines "a" twice`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newVocabulary(tc.table)
			require.EqualError(t, err, tc.want)
		})
	}
}

func TestNewVocabulary_IndexesRows(t *testing.T) {
	v, err := newVocabulary(vocabularyTable{Namespace: "n", DefaultNamespace: "d", Props: []VocabularyRow{{Name: "a"}, {Name: "b"}}})
	require.NoError(t, err)
	assert.Equal(t, "b", v.byName["b"].Name)
}

func TestMustLoadVocabulary_PanicsOnInvalidTables(t *testing.T) {
	assert.PanicsWithValue(t, "oscal: the OSCAL vocabulary table is not valid JSON: unexpected end of JSON input", func() { mustLoadVocabulary([]byte(`{`)) })
	assert.PanicsWithValue(t, "oscal: the OSCAL vocabulary table has no rows", func() {
		mustLoadVocabulary([]byte(`{"namespace":"n","defaultNamespace":"d","props":[]}`))
	})
}
