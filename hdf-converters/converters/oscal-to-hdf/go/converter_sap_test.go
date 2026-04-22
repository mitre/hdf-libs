package oscal

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
)

func TestConvertAssessmentPlanToHDF_EmptyInput(t *testing.T) {
	_, err := ConvertAssessmentPlanToHDF(nil, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertAssessmentPlanToHDF_InvalidJSON(t *testing.T) {
	_, err := ConvertAssessmentPlanToHDF([]byte("not json"), "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestConvertAssessmentPlanToHDF_NotAssessmentPlan(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/catalog-moderate-resolved.json")
	require.NoError(t, err)

	_, err = ConvertAssessmentPlanToHDF(input, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected assessment-plan document")
}

func TestConvertAssessmentPlanToHDF_FedRAMPFixture(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sap-fedramp.json")
	require.NoError(t, err)

	plan, err := ConvertAssessmentPlanToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Plan name derived from metadata title
	assert.NotEmpty(t, plan.Name)
	assert.Contains(t, plan.Name, "fedramp")

	// Assessments populated from reviewed-controls
	assert.NotEmpty(t, plan.Assessments, "assessments should be populated from reviewed-controls")

	// systemRef from import-ssp
	assert.NotNil(t, plan.SystemRef, "systemRef should be set from import-ssp")
	assert.Equal(t, "#7c30125f-c056-4888-9f1a-7ed1b6a1b638", *plan.SystemRef)

	// Generator
	assert.NotNil(t, plan.Generator)
	assert.Equal(t, "hdf-converters", plan.Generator.Name)
	assert.Equal(t, "1.0.0-test", plan.Generator.Version)

	// Integrity
	assert.NotNil(t, plan.Integrity)
	assert.Equal(t, hdf.Sha256, *plan.Integrity.Algorithm)
}

func TestConvertAssessmentPlanToHDF_PlanNameFromMetadata(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sap-fedramp.json")
	require.NoError(t, err)

	plan, err := ConvertAssessmentPlanToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// The title is "[System Name] FedRAMP Security Assessment Plan (SAP)"
	// which should be kebab-cased
	assert.Contains(t, plan.Name, "system-name")
	assert.Contains(t, plan.Name, "security-assessment-plan")
}

func TestConvertAssessmentPlanToHDF_AssessmentsPopulated(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sap-fedramp.json")
	require.NoError(t, err)

	plan, err := ConvertAssessmentPlanToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// The SAP has one control-selection with include-all
	require.NotEmpty(t, plan.Assessments)

	// First assessment should have a baselineRef derived from the import-ssp
	assert.NotEmpty(t, plan.Assessments[0].BaselineRef)
}

func TestConvertAssessmentPlanToHDF_ValidatesAgainstSchema(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sap-fedramp.json")
	require.NoError(t, err)

	plan, err := ConvertAssessmentPlanToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Verify it marshals to valid JSON
	out, err := json.Marshal(plan)
	require.NoError(t, err)

	// Verify it unmarshals back cleanly
	var roundtrip hdf.HDFPlan
	err = json.Unmarshal(out, &roundtrip)
	require.NoError(t, err)
	assert.Equal(t, plan.Name, roundtrip.Name)
	assert.Equal(t, len(plan.Assessments), len(roundtrip.Assessments))
}

func TestSapPlanName(t *testing.T) {
	tests := []struct {
		title    string
		expected string
	}{
		{"FedRAMP SAP Title", "fedramp-sap-title"},
		{"Simple Title", "simple-title"},
		{"", "oscal-assessment-plan"},
	}
	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			assert.Equal(t, tt.expected, ToKebabCase(tt.title, "oscal-assessment-plan"))
		})
	}
}
