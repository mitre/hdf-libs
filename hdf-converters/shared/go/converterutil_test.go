package shared

import (
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInputChecksum(t *testing.T) {
	t.Run("produces sha256 checksum", func(t *testing.T) {
		checksum := InputChecksum([]byte("hello"))
		require.NotNil(t, checksum)
		assert.Equal(t, hdf.Sha256, checksum.Algorithm)
		assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", checksum.Value)
	})

	t.Run("empty input produces valid checksum", func(t *testing.T) {
		checksum := InputChecksum([]byte(""))
		require.NotNil(t, checksum)
		assert.Equal(t, hdf.Sha256, checksum.Algorithm)
		assert.Len(t, checksum.Value, 64)
	})

	t.Run("different input produces different checksum", func(t *testing.T) {
		c1 := InputChecksum([]byte("hello"))
		c2 := InputChecksum([]byte("world"))
		assert.NotEqual(t, c1.Value, c2.Value)
	})
}

func TestBuildNISTCCITags(t *testing.T) {
	t.Run("builds tags with nist only", func(t *testing.T) {
		tags := BuildNISTCCITags([]string{"SA-11", "RA-5"}, nil)
		assert.Len(t, tags, 1)
		nist, ok := tags["nist"].([]interface{})
		require.True(t, ok)
		assert.Equal(t, "SA-11", nist[0])
		assert.Equal(t, "RA-5", nist[1])
		_, hasCCI := tags["cci"]
		assert.False(t, hasCCI)
	})

	t.Run("builds tags with nist and cci", func(t *testing.T) {
		tags := BuildNISTCCITags(
			[]string{"SA-11"},
			[]string{"CCI-001453"},
		)
		assert.Len(t, tags, 2)
		cci, ok := tags["cci"].([]interface{})
		require.True(t, ok)
		assert.Equal(t, "CCI-001453", cci[0])
	})

	t.Run("omits cci when empty slice", func(t *testing.T) {
		tags := BuildNISTCCITags([]string{"SA-11"}, []string{})
		_, hasCCI := tags["cci"]
		assert.False(t, hasCCI)
	})
}

func TestBuildNISTCCITagsWithExtras(t *testing.T) {
	t.Run("adds extra keys", func(t *testing.T) {
		extras := map[string]interface{}{
			"cveid": "CVE-2024-1234",
		}
		tags := BuildNISTCCITagsWithExtras(
			[]string{"SA-11"},
			[]string{"CCI-001453"},
			extras,
		)
		assert.Len(t, tags, 3)
		assert.Equal(t, "CVE-2024-1234", tags["cveid"])
	})

	t.Run("handles nil extras", func(t *testing.T) {
		tags := BuildNISTCCITagsWithExtras(
			[]string{"SA-11"},
			nil,
			nil,
		)
		assert.Len(t, tags, 1)
	})
}

func TestValidateXMLSize_Normal(t *testing.T) {
	err := ValidateXMLSize([]byte("<root/>"), 0)
	assert.NoError(t, err)
}

func TestValidateXMLSize_TooLarge(t *testing.T) {
	big := make([]byte, 51*1024*1024)
	err := ValidateXMLSize(big, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestValidateXMLSize_CustomLimit(t *testing.T) {
	err := ValidateXMLSize([]byte("<root/>"), 5)
	assert.Error(t, err)
}

func TestValidateXMLInput_Clean(t *testing.T) {
	assert.NoError(t, ValidateXMLInput([]byte("<root/>"), 0))
}

func TestValidateXMLInput_WithEntities(t *testing.T) {
	xml := []byte(`<!DOCTYPE foo [<!ENTITY x "y">]><foo/>`)
	err := ValidateXMLInput(xml, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

func TestValidateXMLInput_TooLarge(t *testing.T) {
	big := make([]byte, 51*1024*1024)
	err := ValidateXMLInput(big, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestValidateXMLInput_CustomSizeLimit(t *testing.T) {
	err := ValidateXMLInput([]byte("<root/>"), 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestBuildHDFResults_MinimalFields(t *testing.T) {
	baseline := hdf.EvaluatedBaseline{Name: "test-baseline"}
	now := time.Now().UTC()

	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "test-to-hdf",
		ConverterVersion: "1.0.0",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Timestamp:        &now,
	})

	require.NotNil(t, result)
	assert.Equal(t, []hdf.EvaluatedBaseline{baseline}, result.Baselines)
	require.NotNil(t, result.Generator)
	assert.Equal(t, "test-to-hdf", result.Generator.Name)
	assert.Equal(t, "1.0.0", result.Generator.Version)
	assert.Equal(t, &now, result.Timestamp)
	assert.Nil(t, result.Tool)
	assert.Nil(t, result.Components)
	assert.Nil(t, result.Statistics)
}

func TestBuildHDFResults_WithToolName(t *testing.T) {
	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "grype-to-hdf",
		ConverterVersion: "1.0.0",
		ToolName:         "Grype",
		Baselines:        []hdf.EvaluatedBaseline{},
	})

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Grype", *result.Tool.Name)
	assert.Nil(t, result.Tool.Version)
	assert.Nil(t, result.Tool.Format)
}

func TestBuildHDFResults_WithAllToolFields(t *testing.T) {
	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "sarif-to-hdf",
		ConverterVersion: "1.0.0",
		ToolName:         "Semgrep",
		ToolVersion:      "1.5.0",
		ToolFormat:       "SARIF",
		Baselines:        []hdf.EvaluatedBaseline{},
	})

	require.NotNil(t, result.Tool)
	assert.Equal(t, "Semgrep", *result.Tool.Name)
	assert.Equal(t, "1.5.0", *result.Tool.Version)
	assert.Equal(t, "SARIF", *result.Tool.Format)
}

func TestBuildHDFResults_EmptyToolStringsOmitted(t *testing.T) {
	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "test-to-hdf",
		ConverterVersion: "1.0.0",
		Baselines:        []hdf.EvaluatedBaseline{},
	})

	assert.Nil(t, result.Tool)
}

func TestBuildHDFResults_WithTargetsAndStatistics(t *testing.T) {
	targets := []hdf.Component{{Name: "web-server"}}
	dur := 42.5
	stats := &hdf.Statistics{Duration: &dur}

	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "nessus-to-hdf",
		ConverterVersion: "1.0.0",
		Baselines:        []hdf.EvaluatedBaseline{},
		Components:       targets,
		Statistics:       stats,
	})

	assert.Equal(t, targets, result.Components)
	assert.Equal(t, stats, result.Statistics)
}

func TestBuildHDFResults_ToolPartialFields(t *testing.T) {
	// Only format set, no name/version
	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "test-to-hdf",
		ConverterVersion: "1.0.0",
		ToolFormat:       "XML",
		Baselines:        []hdf.EvaluatedBaseline{},
	})

	require.NotNil(t, result.Tool)
	assert.Nil(t, result.Tool.Name)
	assert.Nil(t, result.Tool.Version)
	assert.Equal(t, "XML", *result.Tool.Format)
}

func TestValidateJSONSize(t *testing.T) {
	t.Run("within limit", func(t *testing.T) {
		err := ValidateJSONSize([]byte(`{"key":"value"}`), "test-converter", 0)
		assert.NoError(t, err)
	})

	t.Run("exceeds custom limit", func(t *testing.T) {
		err := ValidateJSONSize([]byte(`{"key":"value"}`), "test-converter", 5)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "test-converter")
		assert.Contains(t, err.Error(), "exceeds maximum allowed size")
	})

	t.Run("empty input within limit", func(t *testing.T) {
		err := ValidateJSONSize([]byte{}, "test-converter", 0)
		assert.NoError(t, err)
	})

	t.Run("uses default max size", func(t *testing.T) {
		err := ValidateJSONSize([]byte("small"), "test-converter", 0)
		assert.NoError(t, err)
	})
}

func TestDeriveControlType(t *testing.T) {
	cases := []struct {
		tag      string
		expected *hdf.ControlType
		name     string
	}{
		{"AC-3", ptrControlType(hdf.Technical), "AC-3 is technical"},
		{"AC-1", ptrControlType(hdf.Policy), "AC-1 is policy (any *-1)"},
		{"AC-3(1)", ptrControlType(hdf.Technical), "AC-3(1) enhancement follows base"},
		{"AC-3.1", ptrControlType(hdf.Technical), "AC-3.1 dotted enhancement follows base"},
		{"AC-1(1)", ptrControlType(hdf.Policy), "AC-1(1) enhancement of policy stays policy"},
		{"PM-2", ptrControlType(hdf.Management), "PM-2 is management"},
		{"PM-1", ptrControlType(hdf.Policy), "PM-1 is policy via *-1 rule"},
		{"AT-2", ptrControlType(hdf.Operational), "AT-2 is operational"},
		{"IR-4", ptrControlType(hdf.Operational), "IR-4 is operational"},
		{"MA-3", ptrControlType(hdf.Operational), "MA-3 is operational"},
		{"SC-7", ptrControlType(hdf.Technical), "SC-7 is technical"},
		{"SI-2", ptrControlType(hdf.Technical), "SI-2 is technical"},
		{"IA-5", ptrControlType(hdf.Technical), "IA-5 is technical"},
		{"AU-12", ptrControlType(hdf.Operational), "AU-12 is operational"},
		{"CA-2", ptrControlType(hdf.Management), "CA-2 is management"},
		{"SR-3", ptrControlType(hdf.Management), "SR-3 is management"},
		{"ac-3", ptrControlType(hdf.Technical), "lowercase tag is normalized"},
		{"  AC-3  ", ptrControlType(hdf.Technical), "whitespace is trimmed"},
		{"SV-238196", nil, "STIG-prefixed ID is not classified"},
		{"CCI-000192", nil, "CCI ID is not classified"},
		{"XX-9", nil, "unknown family returns nil"},
		{"", nil, "empty string returns nil"},
		{"AC", nil, "missing sub-control returns nil"},
		{"AC-", nil, "trailing dash returns nil"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveControlType(tc.tag)
			if tc.expected == nil {
				assert.Nil(t, got, "expected nil for tag %q", tc.tag)
			} else {
				require.NotNil(t, got, "expected non-nil for tag %q", tc.tag)
				assert.Equal(t, *tc.expected, *got)
			}
		})
	}
}

func TestDeriveControlTypeFromTags(t *testing.T) {
	t.Run("single technical tag", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"AC-3"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Technical, *got)
	})

	t.Run("technical wins over management", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"PM-2", "AC-3"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Technical, *got, "technical beats management")
	})

	t.Run("operational wins over management", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"PM-2", "AT-2"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Operational, *got)
	})

	t.Run("technical wins over operational", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"AT-2", "AC-3"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Technical, *got)
	})

	t.Run("policy wins over nothing", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"AC-1"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Policy, *got)
	})

	t.Run("technical wins over policy", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"AC-1", "SC-7"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Technical, *got)
	})

	t.Run("ignores unknown families", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"SV-12345", "AC-3"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Technical, *got)
	})

	t.Run("empty slice returns nil", func(t *testing.T) {
		got := DeriveControlTypeFromTags(nil)
		assert.Nil(t, got)
	})

	t.Run("all unknown returns nil", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"SV-1", "CCI-1"})
		assert.Nil(t, got)
	})

	t.Run("static-fallback bundle DefaultStaticAnalysisNIST returns nil", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"SA-11", "RA-5"})
		assert.Nil(t, got, "exact-match static fallback bundle carries no per-finding signal")
	})

	t.Run("static-fallback bundle DefaultRemediationNIST returns nil", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"SI-2", "RA-5"})
		assert.Nil(t, got)
	})

	t.Run("static-fallback bundle DefaultComponentManagementNIST returns nil", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"CM-8"})
		assert.Nil(t, got)
	})

	t.Run("static-fallback order-independent", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"RA-5", "SA-11"})
		assert.Nil(t, got)
	})

	t.Run("non-fallback superset bypasses the gate", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"SA-11", "RA-5", "AC-3"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Technical, *got, "real signal (AC-3) wins over fallback-bundle pattern")
	})

	t.Run("standalone real-signal tag not in fallback bundle", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"SA-11"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Management, *got, "single SA-11 (not the bundle) keeps real signal")
	})
}

func TestNISTTagsFromMap(t *testing.T) {
	t.Run("[]string is returned as-is", func(t *testing.T) {
		tags := map[string]interface{}{"nist": []string{"AC-3", "SI-2"}}
		assert.Equal(t, []string{"AC-3", "SI-2"}, NISTTagsFromMap(tags))
	})

	t.Run("[]interface{} of strings is normalized", func(t *testing.T) {
		tags := map[string]interface{}{
			"nist": []interface{}{"AC-3", "SI-2"},
		}
		assert.Equal(t, []string{"AC-3", "SI-2"}, NISTTagsFromMap(tags))
	})

	t.Run("missing key returns nil", func(t *testing.T) {
		tags := map[string]interface{}{"cci": []string{"CCI-1"}}
		assert.Nil(t, NISTTagsFromMap(tags))
	})

	t.Run("empty []string returns nil", func(t *testing.T) {
		tags := map[string]interface{}{"nist": []string{}}
		assert.Nil(t, NISTTagsFromMap(tags))
	})

	t.Run("empty []interface{} returns nil", func(t *testing.T) {
		tags := map[string]interface{}{"nist": []interface{}{}}
		assert.Nil(t, NISTTagsFromMap(tags))
	})

	t.Run("[]interface{} with non-string elements drops them", func(t *testing.T) {
		tags := map[string]interface{}{
			"nist": []interface{}{"AC-3", 42, "SI-2"},
		}
		assert.Equal(t, []string{"AC-3", "SI-2"}, NISTTagsFromMap(tags))
	})

	t.Run("nil tags returns nil", func(t *testing.T) {
		assert.Nil(t, NISTTagsFromMap(nil))
	})

	t.Run("unexpected type returns nil", func(t *testing.T) {
		tags := map[string]interface{}{"nist": "AC-3"}
		assert.Nil(t, NISTTagsFromMap(tags))
	})
}

func TestDeriveVerificationMethod(t *testing.T) {
	t.Run("non-empty code is automated", func(t *testing.T) {
		code := "control 'AC-3' do; impact 0.7; end"
		got := DeriveVerificationMethod(&code)
		require.NotNil(t, got)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *got)
	})

	t.Run("nil code returns nil", func(t *testing.T) {
		got := DeriveVerificationMethod(nil)
		assert.Nil(t, got, "converter must distinguish manual-by-design vs manual-pending-automation")
	})

	t.Run("empty string returns nil", func(t *testing.T) {
		empty := ""
		got := DeriveVerificationMethod(&empty)
		assert.Nil(t, got, "empty code is not a runnable check")
	})
}

func ptrControlType(ct hdf.ControlType) *hdf.ControlType {
	return &ct
}
