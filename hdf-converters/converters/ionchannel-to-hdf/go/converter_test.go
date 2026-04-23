package ionchannel

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "test-0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

func findRequirement(reqs []hdf.EvaluatedRequirement, id string) *hdf.EvaluatedRequirement {
	for i := range reqs {
		if reqs[i].ID == id {
			return &reqs[i]
		}
	}
	return nil
}

// ---- Input validation ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "ionchannel-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertIonChannelToHDF(input, testVersion) },
		MinimalFixture: "minimal.json",
	})
}

func TestConvert_MissingScanSummaries(t *testing.T) {
	input := []byte(`{"analysis_id": "test", "team_id": "test"}`)
	_, err := ConvertIonChannelToHDF(input, testVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scan_summaries is missing")
}

// ---- Minimal fixture ----

func TestConvert_Minimal_BaselineStructure(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Len(t, result.Baselines, 1)
	assert.Equal(t, "Ion Channel SBOM Analysis", result.Baselines[0].Name)
}

func TestConvert_Minimal_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	assert.Equal(t, "Ion Channel Analysis of https://github.com/example-org/example-project.git", *result.Baselines[0].Title)
}

func TestConvert_Minimal_Generator(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "ionchannel-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

func TestConvert_Minimal_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Ion Channel", *result.Tool.Name)
}

func TestConvert_Minimal_RequirementCount(t *testing.T) {
	// minimal.json has 2 top-level deps + 1 sub-dep = 3 unique deps
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Len(t, result.Baselines[0].Requirements, 3)
}

func TestConvert_Minimal_RequirementIDs(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	assert.NotNil(t, findRequirement(reqs, "dependency-expressjs/express"))
	assert.NotNil(t, findRequirement(reqs, "dependency-jshttp/accepts"))
	assert.NotNil(t, findRequirement(reqs, "dependency-lodash/lodash"))
}

func TestConvert_Minimal_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "dependency-expressjs/express")
	require.NotNil(t, req)
	require.NotNil(t, req.Title)
	assert.Equal(t, "Dependency express from expressjs @ 4.18.2 (Required ^4.18.0)", *req.Title)
}

func TestConvert_Minimal_ImpactZero(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		assert.Equal(t, float64(0), req.Impact, "all Ion Channel deps should have impact 0.0")
	}
}

func TestConvert_Minimal_NISTTags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "dependency-expressjs/express")
	require.NotNil(t, req)
	require.NotNil(t, req.Tags)

	nist, ok := req.Tags["nist"]
	require.True(t, ok, "tags should contain nist key")
	nistArr, ok := nist.([]interface{})
	require.True(t, ok)
	assert.Contains(t, nistArr, "CM-8")
}

func TestConvert_Minimal_CCITags(t *testing.T) {
	// CM-8 has no CCI mappings, so the cci key may be absent
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "dependency-expressjs/express")
	require.NotNil(t, req)
	// Just verify tags exist — CCI may be empty for CM-8
	require.NotNil(t, req.Tags)
}

func TestConvert_Minimal_DependencyMetadataInTags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "dependency-expressjs/express")
	require.NotNil(t, req)

	assert.Equal(t, "expressjs", req.Tags["org"])
	assert.Equal(t, "express", req.Tags["name"])
	assert.Equal(t, "npm", req.Tags["type"])
	assert.Equal(t, "4.18.2", req.Tags["version"])
}

func TestConvert_Minimal_SubDependencyTracking(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	// express should list "accepts" as a sub-dependency in tags
	express := findRequirement(result.Baselines[0].Requirements, "dependency-expressjs/express")
	require.NotNil(t, express)
	subDeps, ok := express.Tags["dependencies"]
	require.True(t, ok, "express should have dependencies in tags")
	subArr, ok := subDeps.([]string)
	require.True(t, ok)
	assert.Contains(t, subArr, "accepts")
}

func TestConvert_Minimal_ParentTracking(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	// accepts should have express as a parent
	accepts := findRequirement(result.Baselines[0].Requirements, "dependency-jshttp/accepts")
	require.NotNil(t, accepts)
	parents, ok := accepts.Tags["parentDependencies"]
	require.True(t, ok, "accepts should have parentDependencies in tags")
	parentArr, ok := parents.([]string)
	require.True(t, ok)
	assert.Contains(t, parentArr, "expressjs/express")
}

func TestConvert_Minimal_CodeContainsDependencyJSON(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "dependency-lodash/lodash")
	require.NotNil(t, req)
	require.NotNil(t, req.Code)
	assert.Contains(t, *req.Code, `"name": "lodash"`)
	assert.Contains(t, *req.Code, `"version": "4.17.21"`)
}

func TestConvert_Minimal_Results(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		require.Len(t, req.Results, 1, "each dep should have exactly one notReviewed result")
		assert.Equal(t, hdf.NotReviewed, req.Results[0].Status)
	}
}

func TestConvert_Minimal_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Integrity)
	assert.Equal(t, hdf.Sha256, *result.Baselines[0].Integrity.Algorithm)
	assert.NotEmpty(t, *result.Baselines[0].Integrity.Checksum)
}

// ---- Edge cases fixture ----

func TestConvert_EdgeCases_PythonEditableInstall(t *testing.T) {
	input := loadFixture(t, "input/edge-cases.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "dependency-n/a/-e")
	require.NotNil(t, req)
	require.NotNil(t, req.Title)
	assert.Equal(t, "Python requirements file requirements.txt", *req.Title)
}

func TestConvert_EdgeCases_NAFieldsOmitted(t *testing.T) {
	input := loadFixture(t, "input/edge-cases.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	// "requests" has org="n/a" and requirement="n/a" — those should be omitted from title
	req := findRequirement(result.Baselines[0].Requirements, "dependency-n/a/requests")
	require.NotNil(t, req)
	require.NotNil(t, req.Title)
	assert.Equal(t, "Dependency requests @ 2.31.0", *req.Title)
}

func TestConvert_EdgeCases_NAVersionOmitted(t *testing.T) {
	input := loadFixture(t, "input/edge-cases.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	// "internal-lib" has version="n/a" — should be omitted from title
	req := findRequirement(result.Baselines[0].Requirements, "dependency-example-corp/internal-lib")
	require.NotNil(t, req)
	require.NotNil(t, req.Title)
	assert.Equal(t, "Dependency internal-lib from example-corp (Required >=0.5.0)", *req.Title)
}

func TestConvert_EdgeCases_NonDependencyScansIgnored(t *testing.T) {
	// edge-cases.json has a community scan — should be ignored
	input := loadFixture(t, "input/edge-cases.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	// Should only have 3 deps from the dependency scan
	assert.Len(t, result.Baselines[0].Requirements, 3)
}

// ---- Helper function tests ----

func TestBuildTitle_Standard(t *testing.T) {
	dep := Dependency{
		Name:        "lodash",
		Org:         "lodash",
		Version:     "4.17.21",
		Requirement: "^4.17.0",
		Type:        "npm",
		Package:     "npm",
	}
	assert.Equal(t, "Dependency lodash from lodash @ 4.17.21 (Required ^4.17.0)", buildTitle(dep))
}

func TestBuildTitle_PythonEditable(t *testing.T) {
	dep := Dependency{
		Name:    "-e",
		Org:     "n/a",
		Type:    "pypi",
		Package: "egg",
		File:    "requirements.txt",
	}
	assert.Equal(t, "Python requirements file requirements.txt", buildTitle(dep))
}

func TestBuildTitle_AllNA(t *testing.T) {
	dep := Dependency{
		Name:        "unknown",
		Org:         "n/a",
		Version:     "N/A",
		Requirement: "n/a",
	}
	assert.Equal(t, "Dependency unknown", buildTitle(dep))
}

func TestExtractAllDependencies_Nested(t *testing.T) {
	dep := Dependency{
		Org:  "top",
		Name: "parent",
		Dependencies: []Dependency{
			{
				Org:          "sub",
				Name:         "child",
				Dependencies: []Dependency{},
			},
		},
	}
	result := extractAllDependencies(dep)
	assert.Len(t, result, 2)
	assert.Equal(t, "parent", result[0].Name)
	assert.Equal(t, "child", result[1].Name)
}

func TestExtractAllDependencies_NoDeps(t *testing.T) {
	dep := Dependency{Org: "a", Name: "b"}
	result := extractAllDependencies(dep)
	assert.Len(t, result, 1)
}

func TestBuildDependencyGraph_ParentAssociation(t *testing.T) {
	deps := []Dependency{
		{
			Org:  "parent-org",
			Name: "parent",
			Dependencies: []Dependency{
				{Org: "child-org", Name: "child"},
			},
		},
	}
	graph := buildDependencyGraph(deps)
	assert.Len(t, graph, 2)

	// Find child and check parent
	for _, dep := range graph {
		if dep.Name == "child" {
			assert.Contains(t, dep.ParentDependencies, "parent-org/parent")
		}
	}
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "ionchannel-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertIonChannelToHDF(input, "0.1.0")
	})
}
