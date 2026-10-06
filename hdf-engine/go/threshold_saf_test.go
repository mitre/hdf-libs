package hdfengine

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// SAF CLI accepts a count bound as an object OR as a bare scalar, and a scalar
// means EXACTLY that count — measured in mitre/saf's own threshold command, which
// guards the scalar path with `typeof !== 'object'` and then asserts inequality.
// Four of SAF's seven sample threshold files use the scalar form, so rejecting it
// means rejecting real SAF specs.
//
// The table is shared with the TypeScript peer, which reaches the same rule
// through normalizeThresholdConfig because it does no YAML decoding of its own.
type safBoundCases struct {
	Cases []struct {
		Name  string          `json:"name"`
		Bound json.RawMessage `json:"bound"`
		Want  ThresholdBound  `json:"want"`
	} `json:"cases"`
}

func loadSAFBoundCases(t *testing.T) safBoundCases {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "saf-bound-shorthand-cases.json"))
	require.NoError(t, err)
	var table safBoundCases
	require.NoError(t, json.Unmarshal(data, &table))
	require.NotEmpty(t, table.Cases)
	return table
}

func TestThresholdBoundAcceptsSAFScalarShorthand(t *testing.T) {
	for _, c := range loadSAFBoundCases(t).Cases {
		t.Run(c.Name, func(t *testing.T) {
			var got ThresholdBound
			require.NoError(t, yaml.Unmarshal(c.Bound, &got), "a SAF-shaped bound must decode")
			assert.Equal(t, c.Want, got)
		})
	}
}

// The real SAF files, unmodified — all SEVEN upstream publishes, not a selection.
// Four carry scalar bounds and three do not; every one must decode, because
// "accepts a SAF threshold file" is the card's whole point and a spec that fails
// to parse is not accepted.
func TestRealSAFThresholdFilesDecode(t *testing.T) {
	dir := filepath.Join("..", "testdata", "saf-thresholds")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	decoded := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".yml" {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			require.NoError(t, err)

			var config ThresholdConfig
			// KnownFields, matching the CLI decoder: a SAF file must not merely
			// parse, it must contain no key this engine would silently drop.
			dec := yaml.NewDecoder(bytes.NewReader(raw))
			dec.KnownFields(true)
			require.NoError(t, dec.Decode(&config), "real SAF spec %s must decode with no unknown keys", e.Name())
			assert.NotNil(t, config.Passed, "%s bounds passed", e.Name())
		})
		decoded++
	}
	// Exact, not a floor: at 4 three fixtures could be deleted and this stayed
	// green, so the completeness the provenance record claims would not be pinned.
	require.Equal(t, 7, decoded, "all seven vendored SAF specs must have been read")
}

// The scalar form reaches the VERDICT, not just the parse: an exact bound must
// fail a count on either side of it. A parse-only assertion would pass against a
// decoder that produced an empty bound.
func TestSAFScalarBoundIsExactWhenEvaluated(t *testing.T) {
	var config ThresholdConfig
	require.NoError(t, yaml.Unmarshal([]byte("passed:\n  total: 2\n"), &config))

	exact := StatusCounts{}
	exact.Passed.Total = 2
	assert.Empty(t, ValidateThresholds(&config, &exact, 100, nil), "a count equal to the scalar passes")

	over := StatusCounts{}
	over.Passed.Total = 3
	assert.NotEmpty(t, ValidateThresholds(&config, &over, 100, nil), "one above an exact bound must fail")

	under := StatusCounts{}
	under.Passed.Total = 1
	assert.NotEmpty(t, ValidateThresholds(&config, &under, 100, nil), "one below an exact bound must fail")
}

// A custom UnmarshalYAML can silently switch off the decoder's KnownFields
// checking for the type it takes over, which would turn a typo inside a bound
// into a bound nobody wrote — the exact false green this project refuses. Pinned
// because the shorthand above is what introduced that risk.
func TestScalarShorthandDoesNotWeakenUnknownKeyRejection(t *testing.T) {
	for _, spec := range []string{
		"failed:\n  total:\n    mni: 5\n",           // typo for min
		"failed:\n  total:\n    maximum: 5\n",       // plausible but undefined
		"failed:\n  total:\n    min: 1\n    x: 2\n", // one good key, one junk
	} {
		t.Run(spec, func(t *testing.T) {
			var config ThresholdConfig
			dec := yaml.NewDecoder(bytes.NewReader([]byte(spec)))
			dec.KnownFields(true)
			err := dec.Decode(&config)
			require.Error(t, err, "an unknown key inside a bound must still be refused")
		})
	}

	// And the good shapes still decode, so the guard above is not just rejecting
	// everything.
	for _, spec := range []string{
		"failed:\n  total:\n    min: 1\n",
		"failed:\n  total: 1\n",
		"failed:\n  total:\n    controls: [SV-1]\n",
	} {
		var config ThresholdConfig
		dec := yaml.NewDecoder(bytes.NewReader([]byte(spec)))
		dec.KnownFields(true)
		assert.NoError(t, dec.Decode(&config), "%q must still decode", spec)
	}
}

// A scalar that is not a count must be refused rather than silently becoming
// zero, naming what a bare bound may be.
func TestScalarShorthandRefusesANonCount(t *testing.T) {
	// 1.5 is the important one: node.Decode into an int accepts a !!float and
	// truncates it without error, so the scalar shorthand would turn this into a
	// bound of 1 nobody wrote. A hazard the shorthand introduces — before it,
	// every scalar was a parse error — which is why the tag check is load-bearing.
	for _, spec := range []string{
		"failed:\n  total: high\n",
		"failed:\n  total: 1.5\n",
		"failed:\n  total: true\n",
		"failed:\n  total: []\n",
	} {
		t.Run(spec, func(t *testing.T) {
			var config ThresholdConfig
			err := yaml.Unmarshal([]byte(spec), &config)
			require.Error(t, err, "a non-count bare bound must be refused")
			assert.Contains(t, err.Error(), "whole number of controls")
		})
	}
}

// A merge key is legitimate YAML that go-yaml expands before the value reaches
// the struct, and a repetitive threshold file is exactly where an author reaches
// for one. The hand-rolled key check in UnmarshalYAML refused it until `<<` was
// exempted; nothing pinned that until this.
func TestBoundAcceptsAYAMLMergeKey(t *testing.T) {
	// The anchor sits on a sibling BOUND, not at the top level: the config
	// vocabulary is closed, so a stray top-level `defaults:` key is refused on its
	// own merits before any of this is reached.
	spec := "failed:\n  critical: &d\n    max: 0\n  total:\n    <<: *d\n"

	var config ThresholdConfig
	dec := yaml.NewDecoder(bytes.NewReader([]byte(spec)))
	dec.KnownFields(true)
	require.NoError(t, dec.Decode(&config), "a merge key inside a bound must decode")

	require.NotNil(t, config.Failed)
	require.NotNil(t, config.Failed.Total)
	require.NotNil(t, config.Failed.Total.Max)
	assert.Equal(t, 0, *config.Failed.Total.Max, "the merged value must actually arrive")

	// And the exemption does not open a hole: an unknown key alongside the merge
	// is still refused.
	var bad ThresholdConfig
	badDec := yaml.NewDecoder(bytes.NewReader([]byte("failed:\n  critical: &d\n    max: 0\n  total:\n    <<: *d\n    bogus: 1\n")))
	badDec.KnownFields(true)
	err := badDec.Decode(&bad)
	require.Error(t, err, "a merge key must not smuggle an unknown key past the check")
	assert.Contains(t, err.Error(), "bogus")
}
