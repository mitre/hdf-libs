package oscal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func readInput(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err)
	return data
}

// Every fixture is run through every typed relation: the one whose document
// type matches must land exactly on the conversion's primary-item count, and
// all of them must reject exactly what their conversion rejects.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)

	type relation struct {
		unit    string
		expect  func([]byte) (int, string, error)
		convert func([]byte) (int, error)
	}
	relations := map[string]relation{
		"catalog": {"OSCAL catalog controls at depth two", ExpectedCatalogRequirementCount, func(in []byte) (int, error) {
			b, err := ConvertCatalogToHDF(in, "test")
			if err != nil {
				return 0, err
			}
			return len(b.Requirements), nil
		}},
		"component-definition": {"OSCAL implemented-requirements of the first component", ExpectedComponentDefinitionRequirementCount, func(in []byte) (int, error) {
			b, err := ConvertComponentDefinitionToHDF(in, "test")
			if err != nil {
				return 0, err
			}
			return len(b.Requirements), nil
		}},
		"assessment-plan": {"OSCAL reviewed-control selections", ExpectedAssessmentPlanRequirementCount, func(in []byte) (int, error) {
			p, err := ConvertAssessmentPlanToHDF(in, "test")
			if err != nil {
				return 0, err
			}
			return len(p.Assessments), nil
		}},
		"plan-of-action-and-milestones": {"OSCAL POA&M items", ExpectedPOAMRequirementCount, func(in []byte) (int, error) {
			a, err := ConvertPOAMToHDF(in, "test")
			if err != nil {
				return 0, err
			}
			return len(a.Overrides), nil
		}},
		"assessment-results": {"distinct control ids across OSCAL results with findings", ExpectedAssessmentResultsRequirementCount, func(in []byte) (int, error) {
			r, err := ConvertAssessmentResultsToHDF(in, "test")
			if err != nil {
				return 0, err
			}
			n := 0
			for _, b := range r.Baselines {
				n += len(b.Requirements)
			}
			return n, nil
		}},
	}

	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		for docType, rel := range relations {
			n, convErr := rel.convert(data)
			expected, unit, expErr := rel.expect(data)
			require.Equal(t, convErr != nil, expErr != nil, "%s as %s: converter and expectation must agree on rejection", filepath.Base(path), docType)
			if convErr != nil {
				continue
			}
			require.Equal(t, rel.unit, unit)
			require.Equal(t, n, expected, "relation broken for %s as %s", filepath.Base(path), docType)
		}
	}
}

// Pinned vectors so a fixture drift or a selection change is caught by name.
func TestExpectedRequirementCount_Vectors(t *testing.T) {
	cases := []struct {
		fixture  string
		expect   func([]byte) (int, string, error)
		expected int
	}{
		{"catalog-800-53-rev5.json", ExpectedCatalogRequirementCount, 1196},
		{"component-example.json", ExpectedComponentDefinitionRequirementCount, 2},
		{"sap-fedramp.json", ExpectedAssessmentPlanRequirementCount, 1},
		{"poam-fedramp.json", ExpectedPOAMRequirementCount, 2},
		{"sar-fedramp.json", ExpectedAssessmentResultsRequirementCount, 6},
	}
	for _, c := range cases {
		expected, _, err := c.expect(readInput(t, c.fixture))
		require.NoError(t, err, c.fixture)
		require.Equal(t, c.expected, expected, c.fixture)
	}
}

// The profile relation takes the catalog too; every local profile fixture is
// resolved against every local catalog fixture and must agree with the
// conversion on both the count and the rejection.
func TestExpectedProfileRequirementCount_MatchesConversion(t *testing.T) {
	profiles := []string{"profile-moderate.json", "profile-redhat-fedramp-high.json"}
	catalogs := []string{"catalog-800-53-rev5.json", "catalog-moderate-resolved.json"}
	for _, p := range profiles {
		for _, c := range catalogs {
			profile, catalog := readInput(t, p), readInput(t, c)
			b, convErr := ConvertProfileToHDF(profile, catalog, "test")
			expected, unit, expErr := ExpectedProfileRequirementCount(profile, catalog)
			require.Equal(t, convErr != nil, expErr != nil, "%s against %s: converter and expectation must agree on rejection", p, c)
			if convErr != nil {
				continue
			}
			require.Equal(t, "OSCAL catalog controls selected by the profile", unit)
			require.Equal(t, len(b.Requirements), expected, "relation broken for %s against %s", p, c)
		}
	}

	expected, _, err := ExpectedProfileRequirementCount(readInput(t, "profile-moderate.json"), readInput(t, "catalog-800-53-rev5.json"))
	require.NoError(t, err)
	require.Equal(t, 287, expected)
}

// A POA&M item without a deadline is refused by the conversion; the
// expectation must refuse it identically rather than count the item.
func TestExpectedPOAMRequirementCount_RejectsMissingDeadline(t *testing.T) {
	data := []byte(`{"plan-of-action-and-milestones":{"uuid":"u","metadata":{"title":"t","last-modified":"2024-01-01T00:00:00Z","version":"1","oscal-version":"1.1.2"},"poam-items":[{"uuid":"i","title":"AC-2 gap","description":"d"}]}}`)
	_, convErr := ConvertPOAMToHDF(data, "test")
	require.Error(t, convErr)
	_, _, expErr := ExpectedPOAMRequirementCount(data)
	require.Error(t, expErr)
	require.Equal(t, convErr.Error(), expErr.Error())
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	bad := [][]byte{nil, []byte(""), []byte("garbage"), []byte("{}"), []byte(`{"catalog":{}}`), []byte(`{"component-definition":{}}`)}
	for _, in := range bad {
		_, convErr := ConvertCatalogToHDF(in, "test")
		_, _, expErr := ExpectedCatalogRequirementCount(in)
		require.Equal(t, convErr != nil, expErr != nil, "catalog %q", string(in))

		_, convErr = ConvertComponentDefinitionToHDF(in, "test")
		_, _, expErr = ExpectedComponentDefinitionRequirementCount(in)
		require.Equal(t, convErr != nil, expErr != nil, "component-definition %q", string(in))

		_, convErr = ConvertAssessmentPlanToHDF(in, "test")
		_, _, expErr = ExpectedAssessmentPlanRequirementCount(in)
		require.Equal(t, convErr != nil, expErr != nil, "assessment-plan %q", string(in))

		_, convErr = ConvertPOAMToHDF(in, "test")
		_, _, expErr = ExpectedPOAMRequirementCount(in)
		require.Equal(t, convErr != nil, expErr != nil, "poam %q", string(in))

		_, convErr = ConvertAssessmentResultsToHDF(in, "test")
		_, _, expErr = ExpectedAssessmentResultsRequirementCount(in)
		require.Equal(t, convErr != nil, expErr != nil, "assessment-results %q", string(in))

		_, convErr = ConvertProfileToHDF(in, in, "test")
		_, _, expErr = ExpectedProfileRequirementCount(in, in)
		require.Equal(t, convErr != nil, expErr != nil, "profile %q", string(in))
	}
}
