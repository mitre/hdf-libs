package ionchannel

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

const testVersion = "test-0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
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
	shared.MustFindRequirement(t, reqs, "dependency-expressjs/express")
	shared.MustFindRequirement(t, reqs, "dependency-jshttp/accepts")
	shared.MustFindRequirement(t, reqs, "dependency-lodash/lodash")
}

func TestConvert_Minimal_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "dependency-expressjs/express")
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

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "dependency-expressjs/express")
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

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "dependency-expressjs/express")
	// Just verify tags exist — CCI may be empty for CM-8
	require.NotNil(t, req.Tags)
}

func TestConvert_Minimal_DependencyMetadataInTags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "dependency-expressjs/express")

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
	express := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "dependency-expressjs/express")
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
	accepts := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "dependency-jshttp/accepts")
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

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "dependency-lodash/lodash")
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

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "dependency-n/a/-e")
	require.NotNil(t, req.Title)
	assert.Equal(t, "Python requirements file requirements.txt", *req.Title)
}

func TestConvert_EdgeCases_NAFieldsOmitted(t *testing.T) {
	input := loadFixture(t, "input/edge-cases.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	// "requests" has org="n/a" and requirement="n/a" — those should be omitted from title
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "dependency-n/a/requests")
	require.NotNil(t, req.Title)
	assert.Equal(t, "Dependency requests @ 2.31.0", *req.Title)
}

func TestConvert_EdgeCases_NAVersionOmitted(t *testing.T) {
	input := loadFixture(t, "input/edge-cases.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	// "internal-lib" has version="n/a" — should be omitted from title
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "dependency-example-corp/internal-lib")
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
		return ConvertIonChannelToHDF(input, "1.0.0")
	})
}

func TestConvertIonChannelToHDF_ControlType(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

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
	assert.False(t, sawDerivation, "converter uses static-fallback NIST only; controlType must be omitted per helper gate")
}

func TestConvertIonChannel_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertIonChannelToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)
	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q: ionchannel is an automated SBOM/dependency scanner", req.ID)
	}
}

// countDistinctFlattenedDeps derives the ground-truth requirement count directly
// from the raw JSON, independent of the converter's structs: it recursively
// flattens the "dependency" scan summary's dependency tree and counts each
// distinct org/name exactly once — mirroring the emission unit (one requirement
// per deduped, flattened dependency). A generic CountJSONItemsUnderKey would
// over-count when the same package appears in two subtrees, so the anchor
// re-derives the dedup here rather than reusing the converter's traversal.
func countDistinctFlattenedDeps(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		ScanSummaries []struct {
			Name    string `json:"name"`
			Results struct {
				Data struct {
					Dependencies []json.RawMessage `json:"dependencies"`
				} `json:"data"`
			} `json:"results"`
		} `json:"scan_summaries"`
	}
	require.NoError(t, json.Unmarshal(input, &doc), "anchor: invalid ionchannel JSON")

	seen := map[string]bool{}
	var walk func(raw json.RawMessage)
	walk = func(raw json.RawMessage) {
		var node struct {
			Org          string            `json:"org"`
			Name         string            `json:"name"`
			Dependencies []json.RawMessage `json:"dependencies"`
		}
		require.NoError(t, json.Unmarshal(raw, &node), "anchor: invalid dependency node")
		seen[node.Org+"/"+node.Name] = true
		for _, sub := range node.Dependencies {
			walk(sub)
		}
	}
	for _, scan := range doc.ScanSummaries {
		if scan.Name == "dependency" {
			for _, dep := range scan.Results.Data.Dependencies {
				walk(dep)
			}
		}
	}
	return len(seen)
}

// Ground-truth anchor: one requirement per distinct dependency in the flattened
// "dependency" scan tree. Catches a silent under-extraction that TS/Go golden
// parity cannot see.
func TestConvertIonChannel_DependencyAnchor(t *testing.T) {
	for _, name := range []string{"input/minimal.json", "input/edge-cases.json"} {
		input := loadFixture(t, name)
		result, err := ConvertIonChannelToHDF(input, testVersion)
		require.NoError(t, err)
		shared.AssertRequirementCount(t, result, countDistinctFlattenedDeps(t, input),
			name+": one requirement per distinct flattened dependency")
	}
}
