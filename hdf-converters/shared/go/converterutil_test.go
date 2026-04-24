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
