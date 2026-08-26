package shared

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// hdfSchema resolves a vendored HDF source schema, which the corpus tiers are
// asserted against so a case's HDFValid label can never drift from reality.
func hdfSchema(name string) string {
	return filepath.Join(getSharedDir(), "..", "..", "..", "hdf-validators", "go", "schemas", name)
}

// TestAdversarialCorpus_CoversDocumentedCases pins the corpus contents. A case
// silently disappearing would leave every converter's corpus run green while
// covering less, so the names are asserted explicitly rather than by count.
func TestAdversarialCorpus_CoversDocumentedCases(t *testing.T) {
	wantResults := []string{
		"zero-baselines",
		"no-timestamp",
		"requirement-without-title",
		"requirement-without-code",
		"requirement-without-severity",
		"baselines-missing",
		"baselines-null",
		"baselines-wrong-type",
		"baseline-empty-requirements",
		"requirement-empty-results",
		"requirement-missing-id",
		"top-level-array",
	}
	wantAmendments := []string{
		"override-empty-reason",
		"override-no-milestones",
		"evidence-without-description",
		"overrides-missing",
		"overrides-empty",
		"top-level-array",
	}

	require.Equal(t, wantResults, corpusNames(ResultsCorpus()),
		"ResultsCorpus cases changed — update the documented list deliberately")
	require.Equal(t, wantAmendments, corpusNames(AmendmentsCorpus()),
		"AmendmentsCorpus cases changed — update the documented list deliberately")
}

// TestAdversarialCorpus_TierLabelsMatchTheHDFSchema is the assertion that makes
// the two-tier split trustworthy: a case claiming to be schema-valid HDF is
// validated against the real HDF schema, and a case claiming to be degenerate
// must actually fail it. Without this, a mislabeled case would quietly assert
// the wrong contract on every converter that runs the corpus.
func TestAdversarialCorpus_TierLabelsMatchTheHDFSchema(t *testing.T) {
	for _, tc := range []struct {
		schema string
		cases  []CorpusCase
	}{
		{"hdf-results.schema.json", ResultsCorpus()},
		{"hdf-amendments.schema.json", AmendmentsCorpus()},
	} {
		v := NewSchemaValidator(t, hdfSchema(tc.schema))
		for _, c := range tc.cases {
			t.Run(tc.schema+"/"+c.Name, func(t *testing.T) {
				err := v.Validate(c.Input)
				if c.HDFValid {
					require.NoError(t, err,
						"%s is labeled schema-valid HDF but does not satisfy %s", c.Name, tc.schema)
					return
				}
				require.Error(t, err,
					"%s is labeled degenerate but satisfies %s — it proves nothing about error handling", c.Name, tc.schema)
			})
		}
	}
}

// TestAdversarialCorpus_BothTiersPopulated guards against a refactor that leaves
// one tier empty, which would make the corpus pass vacuously.
func TestAdversarialCorpus_BothTiersPopulated(t *testing.T) {
	for name, cases := range map[string][]CorpusCase{
		"results":    ResultsCorpus(),
		"amendments": AmendmentsCorpus(),
	} {
		var valid, degenerate int
		for _, c := range cases {
			if c.HDFValid {
				valid++
			} else {
				degenerate++
			}
		}
		require.Positive(t, valid, "%s corpus has no schema-valid cases — tier A would pass vacuously", name)
		require.Positive(t, degenerate, "%s corpus has no degenerate cases — tier B would pass vacuously", name)
	}
}

func corpusNames(cases []CorpusCase) []string {
	names := make([]string, 0, len(cases))
	for _, c := range cases {
		names = append(names, c.Name)
	}
	return names
}

// --- Corpus contract ---------------------------------------------------------
//
// CheckCase is the logic every converter delegates its conformance assertion to,
// so a silent regression here would weaken every converter's suite at once. It is
// a pure function precisely so these tests can assert the FAILING outcomes
// directly — the outcomes that matter most and that a subtest-based harness
// cannot express without failing itself.

func TestCheckCase_PanicFailsBothTiers(t *testing.T) {
	v := NewSchemaValidator(t, hdfSchema("hdf-results.schema.json"))
	panics := func([]byte) ([]byte, error) { panic("boom") }

	// A panic is a crash, not a rejection. Tier B is satisfied by an error, so
	// without an explicit panic check a crashing converter would PASS the very
	// tier that exists to catch it. That branch shipped broken once; this pins it.
	for _, valid := range []bool{true, false} {
		c := CorpusCase{Name: "panicker", Input: []byte(`{"baselines":[]}`), HDFValid: valid, Why: "probe"}
		msg := CheckCase(v, c, panics)
		require.Contains(t, msg, "panicked",
			"a panicking converter must fail the case (HDFValid=%v)", valid)
	}
}

func TestCheckCase_TierAContract(t *testing.T) {
	v := NewSchemaValidator(t, hdfSchema("hdf-results.schema.json"))
	c := CorpusCase{Name: "a", Input: []byte(`{}`), HDFValid: true, Why: "probe"}

	t.Run("passes when output satisfies the schema", func(t *testing.T) {
		emitValid := func([]byte) ([]byte, error) { return []byte(`{"baselines":[]}`), nil }
		require.Empty(t, CheckCase(v, c, emitValid))
	})

	t.Run("fails when output violates the schema", func(t *testing.T) {
		emitInvalid := func([]byte) ([]byte, error) { return []byte(`{"baselines":"nope"}`), nil }
		require.Contains(t, CheckCase(v, c, emitInvalid), "does not satisfy the target schema",
			"schema-invalid output must fail — this is the whole point of the harness")
	})

	t.Run("fails when a schema-valid input is rejected", func(t *testing.T) {
		refuse := func([]byte) ([]byte, error) { return nil, errors.New("nope") }
		require.Contains(t, CheckCase(v, c, refuse), "must convert")
	})
}

func TestCheckCase_TierBContract(t *testing.T) {
	v := NewSchemaValidator(t, hdfSchema("hdf-results.schema.json"))
	c := CorpusCase{Name: "b", Input: []byte(`[]`), HDFValid: false, Why: "probe"}

	t.Run("passes when the converter returns an error", func(t *testing.T) {
		refuse := func([]byte) ([]byte, error) { return nil, errors.New("rejected") }
		require.Empty(t, CheckCase(v, c, refuse))
	})

	t.Run("fails when the converter accepts invalid HDF", func(t *testing.T) {
		accept := func([]byte) ([]byte, error) { return []byte(`{"baselines":[]}`), nil }
		require.Contains(t, CheckCase(v, c, accept), "must be rejected, not converted",
			"silently converting HDF-invalid input must fail")
	})

	t.Run("does not validate output for a rejected case", func(t *testing.T) {
		// Tier B says nothing about output shape; only that conversion is refused.
		refuse := func([]byte) ([]byte, error) { return []byte("not even json"), errors.New("rejected") }
		require.Empty(t, CheckCase(v, c, refuse))
	})
}

func TestValidateCorpus_RejectsEmptyCorpus(t *testing.T) {
	// Without this guard a converter could opt in with an empty slice and get a
	// green run that asserted nothing.
	require.ErrorContains(t, ValidateCorpus(nil), "corpus is empty")
	require.ErrorContains(t, ValidateCorpus([]CorpusCase{}), "corpus is empty")
	require.NoError(t, ValidateCorpus(ResultsCorpus()))
}

// TestCorpusGolden pins the corpus in a canonical, cross-language form.
//
// The golden is the contract the TypeScript corpus is verified against, so a
// case added, renamed, retiered, or altered on one side alone fails here or
// there. Go owns regeneration (go test ./shared/go/ -update) and TypeScript only
// verifies, so neither side can quietly redefine the shared corpus to match
// itself.
func TestCorpusGolden(t *testing.T) {
	golden := BuildCorpusGolden(t)
	actual, err := json.MarshalIndent(golden, "", "  ")
	require.NoError(t, err)
	actual = append(actual, '\n')

	path := CorpusGoldenPath()
	if updateSnapshots {
		require.NoError(t, os.WriteFile(path, actual, 0o600))
		t.Logf("updated %s", path)
		return
	}

	expected, err := os.ReadFile(path) //nolint:gosec // test-only, reads a checked-in golden
	require.NoError(t, err, "missing corpus golden; regenerate with: go test ./shared/go/ -update")
	require.JSONEq(t, string(expected), string(actual),
		"corpus changed; if intentional regenerate with: go test ./shared/go/ -update")
}

// TestCanonicalJSON_RemovesLanguageArtifacts pins the two normalisations that
// make cross-language comparison possible at all: key order and HTML escaping.
func TestCanonicalJSON_RemovesLanguageArtifacts(t *testing.T) {
	t.Run("sorts keys", func(t *testing.T) {
		out, err := CanonicalJSON([]byte(`{"b":1,"a":2,"c":{"z":1,"y":2}}`))
		require.NoError(t, err)
		require.Equal(t, `{"a":2,"b":1,"c":{"y":2,"z":1}}`, string(out))
	})

	t.Run("does not escape HTML characters", func(t *testing.T) {
		// Go's default encoder escapes <, > and & to < etc; JSON.stringify
		// does not. Left on, every URL-bearing case would diverge.
		out, err := CanonicalJSON([]byte(`{"u":"a<b>c&d"}`))
		require.NoError(t, err)
		require.Equal(t, `{"u":"a<b>c&d"}`, string(out))
	})

	t.Run("normalizes negative zero", func(t *testing.T) {
		// encoding/json emits "-0" for a negative-zero float64 while
		// JSON.stringify emits "0"; the two are numerically equal, so preserving
		// the sign would fail the parity golden over an unobservable difference.
		out, err := CanonicalJSON([]byte(`{"n":-0}`))
		require.NoError(t, err)
		require.Equal(t, `{"n":0}`, string(out))
	})

	t.Run("escapes the line terminators JSON.stringify leaves literal", func(t *testing.T) {
		// Go escapes U+2028/U+2029 by default; the TS peer escapes them too so the
		// two stay byte-equal (and a bare U+2028 is a JS line terminator).
		in := "{\"u\":\"a\u2028b\"}"
		out, err := CanonicalJSON([]byte(in))
		require.NoError(t, err)
		require.Equal(t, `{"u":"a\u2028b"}`, string(out))
	})

	t.Run("rejects malformed json", func(t *testing.T) {
		_, err := CanonicalJSON([]byte(`{not json`))
		require.Error(t, err)
	})
}
