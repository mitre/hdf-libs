package oscal

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func TestConvertSSPToHDF_EmptyInput(t *testing.T) {
	_, err := ConvertSSPToHDF(nil, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertSSPToHDF_InvalidJSON(t *testing.T) {
	_, err := ConvertSSPToHDF([]byte("not json"), "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestConvertSSPToHDF_NotSSP(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/catalog-moderate-resolved.json")
	require.NoError(t, err)

	_, err = ConvertSSPToHDF(input, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected system-security-plan document")
}

func TestConvertSSPToHDF_Fixture(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/ssp-example.json")
	require.NoError(t, err)

	system, err := ConvertSSPToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// System name from system-characteristics
	assert.Equal(t, "Enterprise Logging and Auditing System", system.Name)

	// Description
	assert.NotNil(t, system.Description)
	assert.Contains(t, *system.Description, "enterprise logging")

	// Version
	assert.NotNil(t, system.Version)
	assert.Equal(t, "1.2", *system.Version)

	// Integrity
	assert.NotNil(t, system.Integrity)
	assert.Equal(t, hdf.Sha256, *system.Integrity.Algorithm)

	// Generator
	assert.NotNil(t, system.Generator)
	assert.Equal(t, "hdf-converters", system.Generator.Name)
	assert.Equal(t, "1.0.0-test", system.Generator.Version)
}

func TestConvertSSPToHDF_Components(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/ssp-example.json")
	require.NoError(t, err)

	system, err := ConvertSSPToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// SSP example has 6 components
	assert.Len(t, system.Components, 6)

	// Check component names are present
	names := make(map[string]bool)
	for _, c := range system.Components {
		names[c.Name] = true
	}
	assert.True(t, names["This System"])
	assert.True(t, names["Logging Server"])
	assert.True(t, names["Enterprise Logging, Monitoring, and Alerting Policy"])
}

func TestConvertSSPToHDF_ComponentTypes(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/ssp-example.json")
	require.NoError(t, err)

	system, err := ConvertSSPToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Find the Logging Server component (type: software)
	var loggingServer *hdf.Component
	for i := range system.Components {
		if system.Components[i].Name == "Logging Server" {
			loggingServer = &system.Components[i]
			break
		}
	}
	require.NotNil(t, loggingServer)
	assert.Equal(t, hdf.Application, loggingServer.Type)
	assert.NotNil(t, loggingServer.Description)
}

func TestConvertSSPToHDF_CategorizationLevel(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/ssp-example.json")
	require.NoError(t, err)

	system, err := ConvertSSPToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// SSP example has confidentiality=moderate, integrity=moderate, availability=low
	// High water mark = moderate
	assert.NotNil(t, system.CategorizationLevel)
	assert.Equal(t, hdf.Moderate, *system.CategorizationLevel)
}

func TestConvertSSPToHDF_AuthorizationStatus(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/ssp-example.json")
	require.NoError(t, err)

	system, err := ConvertSSPToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// SSP example has state: "other" → notYetRequested
	assert.NotNil(t, system.AuthorizationStatus)
	assert.Equal(t, hdf.NotYetRequested, *system.AuthorizationStatus)
}

func TestConvertSSPToHDF_BoundaryDescription(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/ssp-example.json")
	require.NoError(t, err)

	system, err := ConvertSSPToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	assert.NotNil(t, system.BoundaryDescription)
	assert.Contains(t, *system.BoundaryDescription, "authorization boundary")
}

func TestConvertSSPToHDF_SystemIdentifier(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/ssp-example.json")
	require.NoError(t, err)

	system, err := ConvertSSPToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	assert.NotNil(t, system.Identifier)
	assert.Equal(t, "d7456980-9277-4dcb-83cf-f8ff0442623b", *system.Identifier)
	assert.NotNil(t, system.IdentifierScheme)
	assert.Equal(t, "https://ietf.org/rfc/rfc4122", *system.IdentifierScheme)
}

func TestConvertSSPToHDF_BaselineRefs(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/ssp-example.json")
	require.NoError(t, err)

	system, err := ConvertSSPToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// The SSP has control-implementation with au-1, which references
	// several components via by-components in statements.
	// Check that at least one component has baseline refs
	hasBaselineRefs := false
	for _, comp := range system.Components {
		if len(comp.BaselineRefs) > 0 {
			hasBaselineRefs = true
			// All baseline refs should be in NIST notation
			for _, ref := range comp.BaselineRefs {
				assert.Equal(t, "AU-1", ref)
			}
		}
	}
	assert.True(t, hasBaselineRefs, "at least one component should have baseline refs")
}

func TestConvertSSPToHDF_RoundTrip(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/ssp-example.json")
	require.NoError(t, err)

	system, err := ConvertSSPToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	out, err := json.Marshal(system)
	require.NoError(t, err)

	var roundtrip hdf.HDFSystem
	err = json.Unmarshal(out, &roundtrip)
	require.NoError(t, err)
	assert.Equal(t, system.Name, roundtrip.Name)
	assert.Equal(t, len(system.Components), len(roundtrip.Components))
}

func TestConvertSSPToHDF_FedRAMP(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/ssp-fedramp.json")
	if err != nil {
		t.Skip("FedRAMP SSP fixture not available")
	}

	system, err := ConvertSSPToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	assert.NotEmpty(t, system.Name)
	assert.NotEmpty(t, system.Components)
}

func TestSspAuthorizationStatus(t *testing.T) {
	tests := []struct {
		state    string
		expected *hdf.AuthorizationStatus
	}{
		{"operational", ptrAuthStatus(hdf.Authorized)},
		{"under-development", ptrAuthStatus(hdf.PendingAuthorization)},
		{"disposition", ptrAuthStatus(hdf.Revoked)},
		{"other", ptrAuthStatus(hdf.NotYetRequested)},
		{"unknown", nil},
	}
	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			result := sspAuthorizationStatus(tt.state)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, *tt.expected, *result)
			}
		})
	}
}

func TestNormalizeFIPSLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"fips-199-moderate", "moderate"},
		{"fips-199-high", "high"},
		{"fips-199-low", "low"},
		{"moderate", "moderate"},
		{"HIGH", "high"},
		{"unknown", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeFIPSLevel(tt.input))
		})
	}
}

func TestMapOSCALComponentType(t *testing.T) {
	tests := []struct {
		oscalType string
		expected  hdf.Copyright
	}{
		{"software", hdf.Application},
		{"this-system", hdf.Application},
		{"service", hdf.Application},
		{"hardware", hdf.Host},
		{"network", hdf.Network},
		{"database", hdf.Database},
		{"storage", hdf.Artifact},
		{"policy", hdf.Application},
		{"process", hdf.Application},
		{"guidance", hdf.Application},
	}
	for _, tt := range tests {
		t.Run(tt.oscalType, func(t *testing.T) {
			assert.Equal(t, tt.expected, mapOSCALComponentType(tt.oscalType))
		})
	}
}

// ptrAuthStatus returns a pointer to an AuthorizationStatus value.
func ptrAuthStatus(s hdf.AuthorizationStatus) *hdf.AuthorizationStatus {
	return &s
}
