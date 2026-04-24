package nikto_to_hdf

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testConverterVersion = "test-version"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	fixturePath := filepath.Join("..", "fixtures", name)
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", name, err)
	}
	return data
}

func TestConvertNiktoToHDF_BasicStructure(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 4)
}

func TestConvertNiktoToHDF_Generator(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Equal(t, "nikto-to-hdf", result.Generator.Name)
	assert.Equal(t, testConverterVersion, result.Generator.Version)
}

func TestConvertNiktoToHDF_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	assert.Equal(t, "Nikto", *result.Tool.Name)
	assert.Equal(t, "JSON", *result.Tool.Format)
}

func TestConvertNiktoToHDF_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Equal(t, "Host: example.com Port: 80", result.Baselines[0].Name)
}

func TestConvertNiktoToHDF_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	assert.Equal(t, "Nikto Target: Host: example.com Port: 80", *result.Baselines[0].Title)
}

func TestConvertNiktoToHDF_BaselineSummary(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Summary)
	assert.Equal(t, "Apache/2.4.41", *result.Baselines[0].Summary)
}

func TestConvertNiktoToHDF_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.Len(t, result.Baselines[0].ResultsChecksum.Value, 64)
}

func TestConvertNiktoToHDF_AllImpactHalf(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		assert.Equal(t, 0.5, req.Impact, "requirement %s should have impact 0.5", req.ID)
	}
}

func TestConvertNiktoToHDF_AllStatusFailed(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, res := range req.Results {
			assert.Equal(t, hdf.Failed, res.Status, "requirement %s should have status Failed", req.ID)
		}
	}
}

func findRequirement(reqs []hdf.EvaluatedRequirement, id string) *hdf.EvaluatedRequirement {
	for i := range reqs {
		if reqs[i].ID == id {
			return &reqs[i]
		}
	}
	return nil
}

func TestConvertNiktoToHDF_NISTMapped(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "600050")
	require.NotNil(t, req, "requirement 600050 not found")

	nistVal, ok := req.Tags["nist"]
	require.True(t, ok, "nist tag missing")
	nistSlice, ok := nistVal.([]interface{})
	require.True(t, ok, "nist tag not a slice")
	assert.Equal(t, "SI-2", nistSlice[0])
}

func TestConvertNiktoToHDF_NISTUnmapped(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "999957")
	require.NotNil(t, req, "requirement 999957 not found")

	nistVal, ok := req.Tags["nist"]
	require.True(t, ok, "nist tag missing")
	nistSlice, ok := nistVal.([]interface{})
	require.True(t, ok, "nist tag not a slice")
	assert.Len(t, nistSlice, 2)
	assert.Equal(t, "SA-11", nistSlice[0])
	assert.Equal(t, "RA-5", nistSlice[1])
}

func TestConvertNiktoToHDF_CCITags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "600050")
	require.NotNil(t, req)

	cciVal, ok := req.Tags["cci"]
	require.True(t, ok, "cci tag missing")
	cciSlice, ok := cciVal.([]interface{})
	require.True(t, ok, "cci tag not a slice")
	assert.Greater(t, len(cciSlice), 0)
}

func TestConvertNiktoToHDF_OSVDBPresent(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "999971")
	require.NotNil(t, req, "requirement 999971 not found")

	osvdbVal, ok := req.Tags["osvdb"]
	require.True(t, ok, "osvdb tag missing")
	assert.Equal(t, "877", osvdbVal)
}

func TestConvertNiktoToHDF_OSVDBZeroOmitted(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "600050")
	require.NotNil(t, req)

	_, ok := req.Tags["osvdb"]
	assert.False(t, ok, "osvdb tag should be omitted when OSVDB is 0")
}

func TestConvertNiktoToHDF_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "600050")
	require.NotNil(t, req)
	assert.Equal(t, "URL: / Method: HEAD", req.Results[0].CodeDesc)
}

func TestConvertNiktoToHDF_Description(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "999957")
	require.NotNil(t, req)

	require.Len(t, req.Descriptions, 1)
	assert.Equal(t, "default", req.Descriptions[0].Label)
	assert.Equal(t, "The anti-clickjacking X-Frame-Options header is not present.", req.Descriptions[0].Data)
}

func TestConvertNiktoToHDF_TargetName(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Equal(t, "Host: zero.webappsecurity.com Port: 443", result.Baselines[0].Name)
}

func TestConvertNiktoToHDF_EmptyVulns(t *testing.T) {
	input := loadFixture(t, "input/empty-vulns.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 0)
}

func TestConvertNiktoToHDF_FullFixture(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Len(t, result.Baselines[0].Requirements, 14)
}

func TestConvertNiktoToHDF_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "999986")
	require.NotNil(t, req)
	require.NotNil(t, req.Title)
	assert.Equal(t, "Retrieved access-control-allow-origin header: *", *req.Title)
}

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "nikto-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertNiktoToHDF(input, testConverterVersion) },
		MinimalFixture: "minimal.json",
	})
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "nikto-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertNiktoToHDF(input, "0.1.0")
	})
}
