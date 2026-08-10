package nikto_to_hdf

import (
	"encoding/json"
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
	assert.Nil(t, result.Tool.Format, "serialization structures are not formats (kpvj)")
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

func TestConvertNiktoToHDF_NISTMapped(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "600050")

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

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "999957")

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

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "600050")

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

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "999971")

	osvdbVal, ok := req.Tags["osvdb"]
	require.True(t, ok, "osvdb tag missing")
	assert.Equal(t, "877", osvdbVal)
}

func TestConvertNiktoToHDF_OSVDBZeroOmitted(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "600050")

	_, ok := req.Tags["osvdb"]
	assert.False(t, ok, "osvdb tag should be omitted when OSVDB is 0")
}

func TestConvertNiktoToHDF_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "600050")
	assert.Equal(t, "URL: / Method: HEAD", req.Results[0].CodeDesc)
}

func TestConvertNiktoToHDF_Description(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "999957")

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

	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "nikto-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
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

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "999986")
	require.NotNil(t, req.Title)
	assert.Equal(t, "Retrieved access-control-allow-origin header: *", *req.Title)
}

func TestConvertNiktoToHDF_HostComponent(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	comp := result.Components[0]
	assert.Equal(t, hdf.Host, comp.Type)
	assert.Equal(t, "example.com", comp.Name)
	require.NotNil(t, comp.Hostname)
	assert.Equal(t, "example.com", *comp.Hostname)
	require.NotNil(t, comp.IPAddress)
	assert.Equal(t, "93.184.216.34", *comp.IPAddress)
	assert.Nil(t, comp.ComponentID, "componentId must not be set")
}

func TestConvertNiktoToHDF_HostComponentIPOnly(t *testing.T) {
	input := []byte(`{"ip":"10.1.2.3","vulnerabilities":[]}`)
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	comp := result.Components[0]
	assert.Equal(t, hdf.Host, comp.Type)
	assert.Equal(t, "10.1.2.3", comp.Name)
	assert.Nil(t, comp.Hostname)
	require.NotNil(t, comp.IPAddress)
	assert.Equal(t, "10.1.2.3", *comp.IPAddress)
}

func TestConvertNiktoToHDF_HostComponentHostOnly(t *testing.T) {
	input := []byte(`{"host":"web.example.com","vulnerabilities":[]}`)
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	comp := result.Components[0]
	assert.Equal(t, hdf.Host, comp.Type)
	assert.Equal(t, "web.example.com", comp.Name)
	require.NotNil(t, comp.Hostname)
	assert.Equal(t, "web.example.com", *comp.Hostname)
	assert.Nil(t, comp.IPAddress)
}

func TestConvertNiktoToHDF_HostComponentAbsent(t *testing.T) {
	input := []byte(`{"banner":"nginx","vulnerabilities":[]}`)
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Empty(t, result.Components, "no host component when host and ip are absent")
}

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "nikto-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertNiktoToHDF(input, testConverterVersion) },
		MinimalFixture: "minimal.json",
	})
}

func TestSnapshots(t *testing.T) {
	// Nikto JSON carries no scan time (zero-time).
	shared.RunSnapshotTests(t, "nikto-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertNiktoToHDF(input, "unknown")
	}, "*")
}

func TestConvertNikto_ControlType(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	// Nikto resolves NIST tags via niktoId→NIST lookup (with
	// DefaultStaticAnalysisNIST as fallback). At least one requirement
	// should derive a controlType.
	var sawDerivation bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawDerivation = true
			switch *req.ControlType {
			case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
			default:
				t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
			}
		}
	}
	assert.True(t, sawDerivation, "at least one Nikto requirement should have a derived controlType")
}

func TestConvertNiktoToHDF_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)
	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q: Nikto is an automated web server scanner", req.ID)
	}
}

// countDistinctNiktoIDs parses raw Nikto JSON into a minimal local struct —
// deliberately NOT the converter's structs — and returns the number of
// vulnerabilities distinct by id. The converter groups vulnerabilities by id
// (duplicates fold into one requirement with extra results), so a plain array
// count over-counts when ids repeat; this mirrors the grouping independently.
func countDistinctNiktoIDs(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Vulnerabilities []struct {
			ID string `json:"id"`
		} `json:"vulnerabilities"`
	}
	require.NoError(t, json.Unmarshal(input, &doc), "failed to parse Nikto JSON for anchor count")
	distinct := make(map[string]struct{})
	for _, v := range doc.Vulnerabilities {
		distinct[v.ID] = struct{}{}
	}
	return len(distinct)
}

// Ground-truth anchor (input-derived count; see shared/go/anchor.go). Golden
// parity proves Go and TS agree, not that either is correct. Nikto emits one
// requirement per distinct vulnerability id (it groups by id); assert that
// distinct count derived INDEPENDENTLY from the source, so a silent
// under-extraction fails even when both languages agree.
func TestConvertNiktoToHDF_VulnerabilityAnchor(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.json")
	result, err := ConvertNiktoToHDF(input, testConverterVersion)
	require.NoError(t, err)

	want := countDistinctNiktoIDs(t, input)
	shared.AssertRequirementCount(t, result, want,
		"zero.webappsecurity.json: one requirement per distinct vulnerability id")
}
