package shared_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Evaluated_Requirement requires results and descriptions AND gives both
// minItems:1, so an empty array is as invalid as a missing one. Four converters
// shipped a path that emitted one anyway, each found by hand because no fixture
// reaches the path and the schema only runs on documents a test produces. These
// two guards are the cheap standing tripwires for the class: the first catches a
// golden regenerated with the bug, the second catches a test that pins it.
// Validating each golden against the real schema rather than hand-checking
// fields: the first version of this guard tested results and descriptions for
// emptiness and still missed descriptions' contains:{label:"default"}, which a
// zap alert carrying only a solution violates with a non-empty array.
func TestGoldens_ValidateAgainstTheResultsSchema(t *testing.T) {
	root := shared.GetConvertersDir()
	entries, err := os.ReadDir(root)
	require.NoError(t, err)

	checked := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		expected := filepath.Join(root, e.Name(), "fixtures", "expected")
		goldens, readErr := os.ReadDir(expected)
		if readErr != nil {
			continue
		}
		for _, g := range goldens {
			if !strings.HasSuffix(g.Name(), ".json") {
				continue
			}
			raw, fileErr := os.ReadFile(filepath.Join(expected, g.Name()))
			require.NoError(t, fileErr)

			// Only results-shaped goldens; a converter whose target is amendments,
			// baseline or a non-HDF format has its own schema and its own test.
			var probe struct {
				Baselines []struct {
					Requirements []json.RawMessage `json:"requirements"`
				} `json:"baselines"`
			}
			var hasBaselines map[string]json.RawMessage
			if json.Unmarshal(raw, &probe) != nil || json.Unmarshal(raw, &hasBaselines) != nil {
				continue
			}
			if _, ok := hasBaselines["baselines"]; !ok {
				continue // another document type, with its own schema and its own test
			}
			if v := validators.Validate(raw, validators.TypeResults); !v.Valid {
				t.Errorf("%s/%s is not a valid HDF Results document: %s", e.Name(), g.Name(), v.Error())
			}
			for _, b := range probe.Baselines {
				checked += len(b.Requirements)
			}
		}
	}
	require.Positive(t, checked, "the sweep found no golden requirements, so it is proving nothing")
	t.Logf("validated %d golden requirements across the converter corpus", checked)
}

// The four defects survived because tests asserted the invalid shape as the
// contract. A test may legitimately assert an empty array on a document it was
// handed; what it may not do is assert one on converter output.
func TestNoTestPinsAnEmptyRequiredArray(t *testing.T) {
	// Scoped to converter tests and the cross-converter suite: the defect class
	// is HDF requirements a converter emitted. A fetcher asserting its own API
	// envelope is empty (defectdojo) is a different type and a sound assertion.
	pkgRoot := filepath.Dir(shared.GetConvertersDir())
	roots := []string{shared.GetConvertersDir(), filepath.Join(pkgRoot, "test")}

	// Regexes, not substrings: "Empty(t, req.Results)" is a substring of the
	// correct "NotEmpty(t, req.Results)" and flagged 17 sound assertions. Go is
	// covered as well as TypeScript, because every one of the four defects had a
	// Go twin.
	banned := []*regexp.Regexp{
		// TypeScript. The .length).toBe(0) form is the one that let gitlab-to-hdf
		// pin this defect past the first version of this guard.
		regexp.MustCompile(`\.(?:results|descriptions)\)\.toHaveLength\(0\)`),
		regexp.MustCompile(`\.(?:results|descriptions)\.length\)\.toBe\(0\)`),
		regexp.MustCompile(`\.(?:results|descriptions)\)\.(?:toEqual|toStrictEqual)\(\[\]\)`),
		// Go. The trailing [,)] matters: assert.Empty takes an optional message,
		// and anchoring on ")" alone missed every call that passes one.
		regexp.MustCompile(`(?:assert|require)\.Empty\(t, [\w.\[\]]*\.(?:Results|Descriptions)[,)]`),
		regexp.MustCompile(`(?:assert|require)\.Len\(t, [\w.\[\]]*\.(?:Results|Descriptions), 0\)`),
		regexp.MustCompile(`(?:assert|require)\.Equal\(t, 0, len\([\w.\[\]]*\.(?:Results|Descriptions)\)\)`),
	}
	var offenders []string
	walk := func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".test.ts") && !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, b := range banned {
			if m := b.Find(raw); m != nil {
				rel, _ := filepath.Rel(pkgRoot, path)
				offenders = append(offenders, rel+" contains "+string(m))
			}
		}
		return nil
	}
	for _, r := range roots {
		require.NoError(t, filepath.WalkDir(r, walk))
	}
	assert.Emptyf(t, offenders,
		"a test asserts a converter emitted an empty schema-required array, which documents a bug as a contract: %v", offenders)
}
