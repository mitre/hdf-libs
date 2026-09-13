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
