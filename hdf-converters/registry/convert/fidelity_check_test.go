package convert

import (
	"errors"
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
		got, err := CountRequirements([]byte(c.doc))
		require.NoError(t, err, c.name)
		require.Equal(t, c.want, got, c.name)
	}
}

func TestCountRequirements_RejectsUnknownShape(t *testing.T) {
	for _, doc := range []string{`{}`, `{"name":"x"}`, `[]`, `not json`} {
		_, err := CountRequirements([]byte(doc))
		require.Error(t, err, doc)
	}
}

// fidelityStub declares whatever relation the test states; the check never
// converts, so Convert is only there to satisfy the interface.
type fidelityStub struct {
	expect    int
	unit      string
	expectErr error
}

func (s *fidelityStub) Name() string                   { return "Fidelity stub" }
func (s *fidelityStub) Convert([]byte) ([]byte, error) { return nil, nil }
func (s *fidelityStub) ExpectedRequirementCount([]byte) (int, string, error) {
	return s.expect, s.unit, s.expectErr
}

type plainStub struct{}

func (plainStub) Name() string                   { return "Plain stub" }
func (plainStub) Convert([]byte) ([]byte, error) { return nil, nil }

const oneRequirement = `{"baselines":[{"requirements":[{}]}]}`

func TestCheckRequirementFidelity_UncheckedConverters(t *testing.T) {
	note, err := CheckRequirementFidelity(plainStub{}, []byte("in"), []byte(oneRequirement))
	require.NoError(t, err)
	require.Empty(t, note, "a converter with no declared relation is not checked")

	note, err = CheckRequirementFidelity(&fidelityStub{expectErr: ErrNoExpectation}, []byte("in"), []byte(oneRequirement))
	require.NoError(t, err)
	require.Empty(t, note, "a converter stating no relation for this input is not checked")
}

func TestCheckRequirementFidelity_ExpectationErrorIsWrapped(t *testing.T) {
	cause := errors.New("catalog missing")
	_, err := CheckRequirementFidelity(&fidelityStub{expectErr: cause}, []byte("in"), []byte(oneRequirement))
	require.ErrorIs(t, err, cause)
	require.Contains(t, err.Error(), "cannot state the expected requirement count")
}

func TestCheckRequirementFidelity_UncountableOutputIsAnError(t *testing.T) {
	_, err := CheckRequirementFidelity(&fidelityStub{expect: 1, unit: "fake findings"}, []byte("in"), []byte(`{"name":"x"}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot count the converted requirements")
}

func TestCheckRequirementFidelity_MismatchRefuses(t *testing.T) {
	note, err := CheckRequirementFidelity(&fidelityStub{expect: 2, unit: "fake findings"}, []byte("in"), []byte(oneRequirement))
	require.EqualError(t, err, "conversion lost findings: expected 2 requirements from the input's fake findings, produced 1; no output written")
	require.Empty(t, note)
}

func TestCheckRequirementFidelity_MatchReportsTheRelation(t *testing.T) {
	note, err := CheckRequirementFidelity(&fidelityStub{expect: 1, unit: "fake findings"}, []byte("in"), []byte(oneRequirement))
	require.NoError(t, err)
	require.Equal(t, "1 requirement, matching the input's fake findings", note)
}

// --------------------------------------------------------------------------
// The result-side check (ADR-0017 §6).
// --------------------------------------------------------------------------

func TestCountResults_ByDocumentShape(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want int
	}{
		{"results across baselines", `{"baselines":[{"requirements":[{"results":[{},{}]},{"results":[{}]}]},{"requirements":[{"results":[{}]}]}]}`, 4},
		{"baseline top-level requirements", `{"name":"b","requirements":[{"results":[{},{}]}]}`, 2},
		{"a requirement with no results counts zero", `{"baselines":[{"requirements":[{}]}]}`, 0},
	}
	for _, c := range cases {
		got, err := CountResults([]byte(c.doc))
		require.NoError(t, err, c.name)
		require.Equal(t, c.want, got, c.name)
	}
}

// A document with no requirement-bearing shape cannot be checked, and saying so
// is better than reporting zero results.
func TestCountResults_RejectsUnknownShape(t *testing.T) {
	for _, doc := range []string{`{}`, `{"name":"x"}`, `{"overrides":[{}]}`, `not json`} {
		_, err := CountResults([]byte(doc))
		require.Error(t, err, doc)
	}
}

// resultFidelityStub declares a result relation and nothing else.
type resultFidelityStub struct {
	expect    int
	unit      string
	expectErr error
}

func (s *resultFidelityStub) Name() string                   { return "Result fidelity stub" }
func (s *resultFidelityStub) Convert([]byte) ([]byte, error) { return nil, nil }
func (s *resultFidelityStub) ExpectedResultCount([]byte) (int, string, error) {
	return s.expect, s.unit, s.expectErr
}

const oneResult = `{"baselines":[{"requirements":[{"results":[{}]}]}]}`

func TestCheckResultFidelity_UncheckedConverters(t *testing.T) {
	note, err := CheckResultFidelity(plainStub{}, []byte("in"), []byte(oneResult))
	require.NoError(t, err)
	require.Empty(t, note, "a converter with no declared result relation is not checked")

	note, err = CheckResultFidelity(&resultFidelityStub{expectErr: ErrNoExpectation}, []byte("in"), []byte(oneResult))
	require.NoError(t, err)
	require.Empty(t, note, "a converter stating no relation for this input is not checked")
}

func TestCheckResultFidelity_ExpectationErrorIsWrapped(t *testing.T) {
	cause := errors.New("unreadable input")
	_, err := CheckResultFidelity(&resultFidelityStub{expectErr: cause}, []byte("in"), []byte(oneResult))
	require.ErrorIs(t, err, cause)
	require.Contains(t, err.Error(), "cannot state the expected result count")
}

func TestCheckResultFidelity_UncountableOutputIsAnError(t *testing.T) {
	_, err := CheckResultFidelity(&resultFidelityStub{expect: 1, unit: "raw findings"}, []byte("in"), []byte(`{"name":"x"}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot count the converted results")
}

// The whole point of the result anchor: a rolled-up converter's requirement
// count legitimately shrinks, so only the result count still catches a lost
// finding.
func TestCheckResultFidelity_MismatchRefuses(t *testing.T) {
	note, err := CheckResultFidelity(&resultFidelityStub{expect: 2, unit: "raw findings"}, []byte("in"), []byte(oneResult))
	require.EqualError(t, err, "conversion lost findings: expected 2 results from the input's raw findings, produced 1; no output written")
	require.Empty(t, note)
}

func TestCheckResultFidelity_MatchReportsTheRelation(t *testing.T) {
	note, err := CheckResultFidelity(&resultFidelityStub{expect: 1, unit: "raw findings"}, []byte("in"), []byte(oneResult))
	require.NoError(t, err)
	require.Equal(t, "1 result, matching the input's raw findings", note)
}
