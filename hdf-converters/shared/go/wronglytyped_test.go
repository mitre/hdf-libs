package shared

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/require"
)

// wronglyTypedCase is one row of ../testdata/wrongly-typed-cases.json. The
// TypeScript peer reads the same file, so the two languages cannot drift apart
// on what a wrongly-typed document does.
type wronglyTypedCase struct {
	Name   string `json:"name"`
	Accept bool   `json:"accept"`
	Path   []any  `json:"path"`
	Value  any    `json:"value"`
	Why    string `json:"why"`
}

func loadWronglyTyped(t *testing.T) (map[string]any, []wronglyTypedCase) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "wrongly-typed-cases.json"))
	require.NoError(t, err, "read the shared wrongly-typed table")
	var table struct {
		Base  map[string]any     `json:"base"`
		Cases []wronglyTypedCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases)
	return table.Base, table.Cases
}

// applyMutation walks path into a deep copy of base and sets the final key to
// value. An empty path leaves the document untouched, which is how the table
// spells its accept-control case.
func applyMutation(t *testing.T, base map[string]any, path []any, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(base)
	require.NoError(t, err)
	var doc any
	require.NoError(t, json.Unmarshal(raw, &doc))

	if len(path) > 0 {
		node := doc
		for _, step := range path[:len(path)-1] {
			switch k := step.(type) {
			case string:
				m, ok := node.(map[string]any)
				require.True(t, ok, "path step %q expects an object", k)
				node = m[k]
			case float64:
				a, ok := node.([]any)
				require.True(t, ok, "path step %v expects an array", k)
				require.Less(t, int(k), len(a), "index out of range")
				node = a[int(k)]
			default:
				t.Fatalf("unsupported path step %v", step)
			}
		}
		last := path[len(path)-1]
		key, ok := last.(string)
		require.True(t, ok, "the final path step names a field")
		m, ok := node.(map[string]any)
		require.True(t, ok, "the final path step expects an object")
		m[key] = value
	}

	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

// Go decodes HDF into generated structs, so encoding/json rejects a wrongly-typed
// field outright. TypeScript parsed untyped and cast, and `as T` is erased at
// runtime, so the same bytes converted and the bad value reached the output.
// Fourteen of these fifteen documents converted in one language and were rejected
// by the other. Both now validate at the shared guard, so both reject — and the
// unmutated base still converts, proving the guard does not over-reject.
func TestRequireHDFResults_RejectsWronglyTypedFields(t *testing.T) {
	base, cases := loadWronglyTyped(t)
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			input := applyMutation(t, base, tc.Path, tc.Value)
			var doc hdf.HDFResults
			err := RequireHDFResults(input, "test", &doc)
			if tc.Accept {
				require.NoError(t, err, "valid HDF must still convert. %s", tc.Why)
				return
			}
			require.Error(t, err, "a wrongly-typed field must be rejected. %s", tc.Why)
		})
	}
}
