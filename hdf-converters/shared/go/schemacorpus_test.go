package shared

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/require"
)

// hdfSchema resolves a vendored HDF source schema, which the corpus contracts are
// asserted against so a case's contract can never drift from reality.
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

// TestAdversarialCorpus_ContractsPopulated guards against a refactor that leaves
// a contract unrepresented, which would make that obligation pass vacuously for
// every converter.
func TestAdversarialCorpus_ContractsPopulated(t *testing.T) {
	for name, cases := range map[string][]CorpusCase{
		"results":    ResultsCorpus(),
		"amendments": AmendmentsCorpus(),
	} {
		counts := map[CorpusContract]int{}
		for _, c := range cases {
			counts[c.Contract]++
		}
		require.Positive(t, counts[MustConvert], "%s corpus has no MustConvert cases", name)
		require.Positive(t, counts[MustReject], "%s corpus has no MustReject cases", name)
	}

	// Only the results corpus carries nested cases today: every amendments
	// defect the schema can express is top-level (a missing or empty overrides
	// array). Asserted rather than left implicit so adding a nested amendments
	// case is a deliberate act.
	var nested int
	for _, c := range ResultsCorpus() {
		if c.Contract == MustNotCorrupt {
			nested++
		}
	}
	require.Positive(t, nested, "results corpus has no MustNotCorrupt cases")
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

func TestCheckCase_PanicFailsEveryContract(t *testing.T) {
	v := NewSchemaValidator(t, hdfSchema("hdf-results.schema.json"))
	panics := func([]byte) ([]byte, error) { panic("boom") }

	// A panic is a crash, not a rejection. MustReject is satisfied by an error, so
	// without an explicit panic check a crashing converter would PASS the very
	// contract that exists to catch it. That branch shipped broken once; this pins it.
	for _, contract := range []CorpusContract{MustConvert, MustReject, MustNotCorrupt} {
		c := CorpusCase{Name: "panicker", Input: []byte(`{"baselines":[]}`), Contract: contract, Why: "probe"}
		msg := CheckCase(v, c, panics)
		require.Contains(t, msg, "panicked",
			"a panicking converter must fail the case (contract=%v)", contract)
	}
}

func TestCheckCase_MustConvertContract(t *testing.T) {
	v := NewSchemaValidator(t, hdfSchema("hdf-results.schema.json"))
	c := CorpusCase{Name: "a", Input: []byte(`{}`), Contract: MustConvert, Why: "probe"}

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

func TestCheckCase_MustRejectContract(t *testing.T) {
	v := NewSchemaValidator(t, hdfSchema("hdf-results.schema.json"))
	c := CorpusCase{Name: "b", Input: []byte(`[]`), Contract: MustReject, Why: "probe"}

	t.Run("passes when the converter returns an error", func(t *testing.T) {
		refuse := func([]byte) ([]byte, error) { return nil, errors.New("rejected") }
		require.Empty(t, CheckCase(v, c, refuse))
	})

	t.Run("fails when the converter accepts invalid HDF", func(t *testing.T) {
		accept := func([]byte) ([]byte, error) { return []byte(`{"baselines":[]}`), nil }
		require.Contains(t, CheckCase(v, c, accept), "must not be converted",
			"silently converting HDF-invalid input must fail")
	})

	t.Run("does not validate output for a rejected case", func(t *testing.T) {
		// MustReject says nothing about output shape; only that conversion is refused.
		refuse := func([]byte) ([]byte, error) { return []byte("not even json"), errors.New("rejected") }
		require.Empty(t, CheckCase(v, c, refuse))
	})
}

// TestCheckCase_MustNotCorruptContract pins the contract that exists precisely
// because no converter validates nested content: either outcome is acceptable,
// but converting nested-invalid input into an invalid document is not. This is
// the obligation that catches a converter emitting an out-of-pattern identifier
// from a requirement with no id.
func TestCheckCase_MustNotCorruptContract(t *testing.T) {
	v := NewSchemaValidator(t, hdfSchema("hdf-results.schema.json"))
	c := CorpusCase{
		Name:     "nested",
		Input:    []byte(`{"baselines":[{"name":"b","requirements":[]}]}`),
		Contract: MustNotCorrupt,
		Why:      "probe",
	}

	t.Run("passes when the converter rejects", func(t *testing.T) {
		refuse := func([]byte) ([]byte, error) { return nil, errors.New("strict") }
		require.Empty(t, CheckCase(v, c, refuse), "refusing nested-invalid input is defensible")
	})

	t.Run("passes when the converter tolerates it and emits valid output", func(t *testing.T) {
		tolerant := func([]byte) ([]byte, error) { return []byte(`{"baselines":[]}`), nil }
		require.Empty(t, CheckCase(v, c, tolerant), "tolerating nested-invalid input is also defensible")
	})

	t.Run("fails when the converter emits an invalid document", func(t *testing.T) {
		corrupt := func([]byte) ([]byte, error) { return []byte(`{"baselines":"nope"}`), nil }
		require.Contains(t, CheckCase(v, c, corrupt), "target schema rejects",
			"converting nested-invalid input into an invalid document is never acceptable")
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
// case added, renamed, reclassified, or altered on one side alone fails here or
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

	expected, err := os.ReadFile(path)
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

// --- Contract classification --------------------------------------------------

// TestCorpusContracts_AreExplicitAndCorrectlyAssigned pins the three-way split.
// A single "HDF-invalid must be rejected" rule conflated two different
// obligations: a document whose TOP-LEVEL shape is wrong is not the type it
// claims and must be refused, while a document that is merely wrong in nested
// content is something no converter validates — the shared guard is deliberately
// top-level only — so demanding rejection there asserted something no converter
// satisfies, which forced per-converter exemptions. This table pins the current
// names; the derivation test below is what stops a NEW case being mislabelled.
func TestCorpusContracts_AreExplicitAndCorrectlyAssigned(t *testing.T) {
	want := map[string]CorpusContract{
		// Sparse but schema-valid HDF.
		"zero-baselines":               MustConvert,
		"no-timestamp":                 MustConvert,
		"requirement-without-title":    MustConvert,
		"requirement-without-code":     MustConvert,
		"requirement-without-severity": MustConvert,
		// Top-level shape is wrong: the document is not HDF Results at all.
		"baselines-missing":    MustReject,
		"baselines-null":       MustReject,
		"baselines-wrong-type": MustReject,
		"top-level-array":      MustReject,
		// Nested content is wrong, but the top level is a well-formed results doc.
		"baseline-empty-requirements": MustNotCorrupt,
		"requirement-empty-results":   MustNotCorrupt,
		"requirement-missing-id":      MustNotCorrupt,
	}

	wantAmendments := map[string]CorpusContract{
		"override-empty-reason":        MustConvert,
		"override-no-milestones":       MustConvert,
		"evidence-without-description": MustConvert,
		"overrides-missing":            MustReject,
		"overrides-empty":              MustReject,
		"top-level-array":              MustReject,
	}

	for _, tc := range []struct {
		label string
		want  map[string]CorpusContract
		cases []CorpusCase
	}{
		{"results", want, ResultsCorpus()},
		{"amendments", wantAmendments, AmendmentsCorpus()},
	} {
		for _, c := range tc.cases {
			got, ok := tc.want[c.Name]
			require.True(t, ok, "%s/%s has no documented contract — classify it deliberately", tc.label, c.Name)
			require.Equal(t, got, c.Contract, "%s/%s carries the wrong contract", tc.label, c.Name)
		}
		require.Len(t, tc.cases, len(tc.want), "%s corpus size changed", tc.label)
	}
}

// TestCorpusContracts_AreDerivableFromTheSchemaAndGuard makes the classification
// mechanically checkable rather than a matter of assertion, which is what the
// hardcoded table above alone could not do: that table pins the current names,
// but nothing stopped a NEW case being mislabelled.
//
// Each contract has an observable definition:
//
//	MustConvert    — the HDF schema accepts it.
//	MustReject     — the schema rejects it AND the shared top-level guard
//	                 rejects it, which is what "top-level shape is wrong" means.
//	MustNotCorrupt — the schema rejects it but the guard ACCEPTS it, i.e. the
//	                 defect is nested, below what any converter validates.
//
// Downgrading MustReject to MustNotCorrupt to make a converter pass therefore
// fails here, because the guard still rejects the input.
func TestCorpusContracts_AreDerivableFromTheSchemaAndGuard(t *testing.T) {
	for _, tc := range []struct {
		schema string
		cases  []CorpusCase
		guard  func([]byte) error
	}{
		{"hdf-results.schema.json", ResultsCorpus(), func(in []byte) error {
			var out hdf.HDFResults
			return RequireHDFResults(in, "probe", &out)
		}},
		{"hdf-amendments.schema.json", AmendmentsCorpus(), func(in []byte) error {
			var out hdf.HDFAmendments
			return RequireHDFAmendments(in, "probe", &out)
		}},
	} {
		v := NewSchemaValidator(t, hdfSchema(tc.schema))
		for _, c := range tc.cases {
			t.Run(tc.schema+"/"+c.Name, func(t *testing.T) {
				schemaErr := v.Validate(c.Input)
				guardErr := tc.guard(c.Input)

				switch c.Contract {
				case MustConvert:
					require.NoError(t, schemaErr, "%s is MustConvert but is not schema-valid HDF", c.Name)
				case MustReject:
					require.Error(t, schemaErr, "%s is MustReject but satisfies the HDF schema", c.Name)
					require.Error(t, guardErr,
						"%s is MustReject but the top-level guard accepts it — its defect is nested, so it is MustNotCorrupt", c.Name)
				case MustNotCorrupt:
					require.Error(t, schemaErr, "%s is MustNotCorrupt but satisfies the HDF schema", c.Name)
					require.NoError(t, guardErr,
						"%s is MustNotCorrupt but the top-level guard rejects it — its defect is structural, so it is MustReject", c.Name)
				}
			})
		}
	}
}
