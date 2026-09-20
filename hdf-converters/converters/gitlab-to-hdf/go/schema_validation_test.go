package gitlab_to_hdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
)

// Every input fixture must satisfy the GitLab report schema for the type and
// version it declares. The fixtures are authored here, so this is the fixture
// policy's validation requirement made mechanical: a document a real GitLab
// pipeline would reject is not evidence that the converter handles real data.
func absPath(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	require.NoError(t, err)
	return abs
}

func TestGitLabFixturesValidateAgainstDeclaredSchema(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	sort.Strings(inputs)

	for _, path := range inputs {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path) // #nosec G304 -- repo-relative fixture
			require.NoError(t, err)
			var header struct {
				Version string `json:"version"`
				Scan    struct {
					Type string `json:"type"`
				} `json:"scan"`
			}
			require.NoError(t, json.Unmarshal(raw, &header))
			require.NotEmpty(t, header.Scan.Type, "fixture declares no scan.type")
			require.NotEmpty(t, header.Version, "fixture declares no report version")

			schemaPath := filepath.Join("..", "fixtures", header.Scan.Type+"-report-format-"+header.Version+".json")
			_, statErr := os.Stat(schemaPath)
			require.NoError(t, statErr, "no vendored schema for scan.type %q at version %s — vendor it with provenance", header.Scan.Type, header.Version)

			schema, err := gojsonschema.NewSchema(gojsonschema.NewReferenceLoader("file://" + absPath(t, schemaPath)))
			require.NoError(t, err)
			result, err := schema.Validate(gojsonschema.NewBytesLoader(raw))
			require.NoError(t, err)
			for _, e := range result.Errors() {
				t.Errorf("%s: %s", e.Field(), e.Description())
			}
		})
	}
}
