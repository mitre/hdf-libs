package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Minimal HDF results with two targets and two baselines.
const minimalResultsJSON = `{
  "baselines": [
    {
      "name": "RHEL9-STIG",
      "checksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"},
      "supports": [],
      "requirements": [],
      "groups": [],
      "depends": [],
      "inputs": []
    },
    {
      "name": "Container-STIG",
      "checksum": {"algorithm": "sha256", "value": "1111111111111111111111111111111111111111111111111111111111111111"},
      "supports": [],
      "requirements": [],
      "groups": [],
      "depends": [],
      "inputs": []
    }
  ],
  "components": [
    {"name": "web-server-01", "type": "host"},
    {"name": "my-container", "type": "containerImage"}
  ],
  "statistics": {"duration": 120.5},
  "generator": {"name": "inspec", "version": "5.0"}
}`

func TestSystemCreate_Basic(t *testing.T) {
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))

	outFile := filepath.Join(t.TempDir(), "system.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile, "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	// System name derived from first target
	assert.Equal(t, "web-server-01", sys["name"])

	// Components created from targets
	components, ok := sys["components"].([]interface{})
	require.True(t, ok)
	assert.Len(t, components, 2)

	// First component
	c0, ok := components[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "web-server-01", c0["name"])
	assert.Equal(t, "host", c0["type"]) // identity mapping post-v3.3.0

	// Check baselineRefs are set from baselines
	refs0, ok := c0["baselineRefs"].([]interface{})
	require.True(t, ok)
	assert.Len(t, refs0, 2) // both baselines referenced

	// Second component
	c1, ok := components[1].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "my-container", c1["name"])
	assert.Equal(t, "containerImage", c1["type"]) // identity mapping post-v3.3.0

	// DataFlows should be empty array
	dataFlows, ok := sys["dataFlows"].([]interface{})
	require.True(t, ok)
	assert.Empty(t, dataFlows)

	// Generator metadata
	gen, ok := sys["generator"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "hdf-cli", gen["name"])
}

func TestSystemCreate_NameFlag(t *testing.T) {
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))

	outFile := filepath.Join(t.TempDir(), "system.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile, "--name", "My Custom System", "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))
	assert.Equal(t, "My Custom System", sys["name"])
}

func TestSystemCreate_OwnerFlag(t *testing.T) { //nolint:dupl
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))

	outFile := filepath.Join(t.TempDir(), "system.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile, "--owner", "platform-team@agency.gov", "-o", outFile})

	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	owner, ok := sys["owner"].(map[string]interface{})
	require.True(t, ok, "owner should be present")
	assert.Equal(t, "email", owner["type"])
	assert.Equal(t, "platform-team@agency.gov", owner["identifier"])
}

func TestSystemCreate_OwnerPlainText(t *testing.T) { //nolint:dupl
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))

	outFile := filepath.Join(t.TempDir(), "system.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile, "--owner", "Platform Engineering Team", "-o", outFile})

	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	owner, ok := sys["owner"].(map[string]interface{})
	require.True(t, ok, "owner should be present")
	assert.Equal(t, "simple", owner["type"])
	assert.Equal(t, "Platform Engineering Team", owner["identifier"])
}

func TestSystemCreate_SystemIdFlag(t *testing.T) { //nolint:dupl
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))

	outFile := filepath.Join(t.TempDir(), "system.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile, "--system-id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "-o", outFile})

	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))
	assert.Equal(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", sys["systemId"])
}

func TestSystemCreate_AutoGeneratesSystemId(t *testing.T) {
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))

	outFile := filepath.Join(t.TempDir(), "system.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile, "-o", outFile})

	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	systemID, ok := sys["systemId"].(string)
	require.True(t, ok, "systemId should be auto-generated")
	assert.Len(t, systemID, 36, "should be a UUID")
}

func TestSystemCreate_DescriptionFlag(t *testing.T) { //nolint:dupl
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))

	outFile := filepath.Join(t.TempDir(), "system.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile, "--description", "Production web application system", "-o", outFile})

	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))
	assert.Equal(t, "Production web application system", sys["description"])
}

func TestSystemCreate_Stdout(t *testing.T) {
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile})

	// Should succeed (output to stdout)
	err := cmd.Execute()
	require.NoError(t, err)
}

func TestSystemCreate_MissingPositional(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create"})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "arg")
}

func TestSystemCreate_MissingFile(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "/nonexistent/results.json"})

	err := cmd.Execute()
	assert.Error(t, err)
}

func TestSystemCreate_InvalidJSON(t *testing.T) {
	resultsFile := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte("not json"), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestSystemCreate_NoTargets(t *testing.T) {
	noTargets := `{
		"baselines": [{"name": "B1", "checksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"}, "supports": [], "requirements": [], "groups": [], "depends": [], "inputs": []}],
		"components": [],
		"statistics": {"duration": 1},
		"generator": {"name": "test", "version": "1.0"}
	}`
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(noTargets), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no targets")
}

func TestSystemCreate_TargetLabelsAsSelector(t *testing.T) {
	withLabels := `{
		"baselines": [{"name": "B1", "checksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"}, "supports": [], "requirements": [], "groups": [], "depends": [], "inputs": []}],
		"components": [
			{"name": "labeled-host", "type": "host", "labels": {"env": "prod", "tier": "web"}}
		],
		"statistics": {"duration": 1},
		"generator": {"name": "test", "version": "1.0"}
	}`
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(withLabels), 0o600))

	outFile := filepath.Join(t.TempDir(), "system.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile, "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	components, ok := sys["components"].([]interface{})
	require.True(t, ok)
	require.Len(t, components, 1)

	c0, ok := components[0].(map[string]interface{})
	require.True(t, ok)

	sel, ok := c0["targetSelector"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "prod", sel["env"])
	assert.Equal(t, "web", sel["tier"])
}

// ---- SBOM input tests ----

func TestSystemCreate_FromCycloneDXSBOM(t *testing.T) {
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/juice-shop-sbom-minimal.json")
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	// Component name auto-detected from metadata.component.name
	components := sys["components"].([]interface{})
	require.Len(t, components, 1)
	c0 := components[0].(map[string]interface{})
	assert.Equal(t, "juice-shop", c0["name"])
	assert.Equal(t, "application", c0["type"])
	boms := c0["boms"].([]interface{})
	require.Len(t, boms, 1)
	bom0 := boms[0].(map[string]interface{})
	assert.Equal(t, "sbom", bom0["bomType"])
	assert.Equal(t, "cyclonedx", bom0["format"])
	assert.Contains(t, bom0["ref"], "juice-shop-sbom-minimal.json")
	assert.Contains(t, c0["description"].(string), "19.1.1") // version extracted
}

func TestSystemCreate_FromSBOM_RequiresComponentNameWhenNoMetadata(t *testing.T) {
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/spdx-to-cyclonedx.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "component-name")
}

func TestSystemCreate_FromSBOM_WithExplicitComponentName(t *testing.T) {
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/spdx-to-cyclonedx.json")
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "--component-name", "MyLib", "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))
	components := sys["components"].([]interface{})
	c0 := components[0].(map[string]interface{})
	assert.Equal(t, "MyLib", c0["name"])
}

func TestSystemCreate_FromURL_RequiresComponentName(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "https://example.com/sbom.cdx.json"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "component-name")
	assert.Contains(t, err.Error(), "URL")
}

func TestSystemCreate_FromURL_WithComponentName(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "https://artifacts.example.com/sbom/webtier.cdx.json", "--component-name", "WebTier", "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))
	components := sys["components"].([]interface{})
	c0 := components[0].(map[string]interface{})
	assert.Equal(t, "WebTier", c0["name"])
	boms := c0["boms"].([]interface{})
	require.Len(t, boms, 1)
	bom0 := boms[0].(map[string]interface{})
	assert.Equal(t, "sbom", bom0["bomType"])
	assert.Equal(t, "https://artifacts.example.com/sbom/webtier.cdx.json", bom0["ref"])
	assert.Equal(t, "cyclonedx", bom0["format"]) // guessed from .cdx.json
}

// URL inputs route through runSystemCreateFromSBOMRef, which must still honor
// the system-level flags (they were silently dropped before).
func TestSystemCreate_FromURL_HonorsSystemFlags(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "https://artifacts.example.com/sbom/webtier.cdx.json",
		"--component-name", "WebTier",
		"--owner", "team@agency.gov",
		"--description", "Prod web tier",
		"--system-id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"--generate-component-id",
		"-o", outFile})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	assert.Equal(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", sys["systemId"])
	assert.Equal(t, "Prod web tier", sys["description"])
	owner, ok := sys["owner"].(map[string]interface{})
	require.True(t, ok, "owner should be present")
	assert.Equal(t, "team@agency.gov", owner["identifier"])

	c0 := sys["components"].([]interface{})[0].(map[string]interface{})
	id, ok := c0["componentId"].(string)
	assert.True(t, ok, "component should have a generated componentId")
	assert.Len(t, id, 36)
}

// --embed cannot embed content that is never fetched, so a URL + --embed errors.
func TestSystemCreate_FromURL_EmbedRejected(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "https://artifacts.example.com/sbom/webtier.cdx.json",
		"--component-name", "WebTier", "--embed"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "embed")
	assert.Contains(t, err.Error(), "URL")
}

// A URL with no format hint keeps a defaulted format (schema-required).
func TestSystemCreate_FromURL_DefaultsFormatNoHint(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "https://artifacts.example.com/sbom/blob", "--component-name", "Blob", "-o", outFile})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	c0 := sys["components"].([]interface{})[0].(map[string]interface{})
	bom0 := c0["boms"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "cyclonedx", bom0["format"]) // defaulted when the URL gives no hint
}

// Oversized input must be rejected by the size gate before it is fully parsed.
func TestSystemCreate_OversizedInputRejected(t *testing.T) {
	big := make([]byte, 2*1024*1024)
	for i := range big {
		big[i] = 'a'
	}
	f := filepath.Join(t.TempDir(), "big.json")
	require.NoError(t, os.WriteFile(f, big, 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", f, "--max-size", "1"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum allowed size")
}

// ---- AI-model BOM input tests ----

func TestSystemCreate_FromAIModelBOM(t *testing.T) {
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", bomFile, "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	components := sys["components"].([]interface{})
	require.Len(t, components, 1)
	c0 := components[0].(map[string]interface{})
	assert.Equal(t, "aiModel", c0["type"])
	assert.Equal(t, "stable-diffusion", c0["name"])
	assert.Equal(t, "1.4", c0["version"])
	assert.Equal(t, "component-a", c0["modelId"]) // bom-ref (no purl in fixture)

	boms := c0["boms"].([]interface{})
	require.Len(t, boms, 1)
	bom0 := boms[0].(map[string]interface{})
	assert.Equal(t, "ai-model", bom0["bomType"])
	assert.Equal(t, "cyclonedx-ml", bom0["format"])

	model := bom0["model"].(map[string]interface{})
	assert.Equal(t, "The architecture of the model.", model["modelArchitecture"])
	// Partial-fidelity: never fabricated.
	_, hasParamCount := model["parameterCount"]
	assert.False(t, hasParamCount)
	_, hasSerFmt := model["serializationFormat"]
	assert.False(t, hasSerFmt)
}

func TestSystemCreate_FromAIModelBOM_Sparse(t *testing.T) {
	bomFile := bomFixturePath(t, "cyclonedx-mlbom-sparse.json")
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", bomFile, "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	c0 := sys["components"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "aiModel", c0["type"])
	assert.Equal(t, "stable-diffusion", c0["name"])

	bom0 := c0["boms"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "ai-model", bom0["bomType"])
	assert.Equal(t, "cyclonedx-ml", bom0["format"])

	// Partial-fidelity: the model extension is minimal/empty and NEVER carries
	// fabricated fields.
	if model, ok := bom0["model"].(map[string]interface{}); ok {
		assert.Empty(t, model)
		_, hasArch := model["modelArchitecture"]
		assert.False(t, hasArch)
		_, hasParamCount := model["parameterCount"]
		assert.False(t, hasParamCount)
	}
}

func TestSystemCreate_FromAIModelBOM_ComponentNameOverride(t *testing.T) {
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", bomFile, "--component-name", "MyModel", "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))
	c0 := sys["components"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "MyModel", c0["name"])
	assert.Equal(t, "aiModel", c0["type"])
}

// componentsByType groups a system document's components by their type value.
func componentsByType(t *testing.T, sys map[string]interface{}) map[string][]map[string]interface{} {
	t.Helper()
	out := map[string][]map[string]interface{}{}
	for _, c := range sys["components"].([]interface{}) {
		comp := c.(map[string]interface{})
		typ, _ := comp["type"].(string)
		out[typ] = append(out[typ], comp)
	}
	return out
}

func TestSystemCreate_FromSPDX3AIBOM(t *testing.T) {
	bomFile := bomFixturePath(t, "spdx-ai-model-1.json")
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", bomFile, "-o", outFile})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	byType := componentsByType(t, sys)
	require.Len(t, byType["aiModel"], 2)
	require.Len(t, byType["dataset"], 1)

	// Every emitted component carries exactly one spdx-3-ai BOM.
	for _, comp := range sys["components"].([]interface{}) {
		boms := comp.(map[string]interface{})["boms"].([]interface{})
		require.Len(t, boms, 1)
		assert.Equal(t, "spdx-3-ai", boms[0].(map[string]interface{})["format"])
	}

	model0 := byType["aiModel"][0]
	assert.NotEmpty(t, model0["modelId"])
	assert.Equal(t, "ai-model", model0["boms"].([]interface{})[0].(map[string]interface{})["bomType"])

	ds0 := byType["dataset"][0]
	assert.NotEmpty(t, ds0["datasetId"])
	assert.Equal(t, "dataset", ds0["boms"].([]interface{})[0].(map[string]interface{})["bomType"])

	// writeSystemDoc validates against the bundled schema before writing, so a
	// successful write already proves schema-validity; assert it explicitly too.
	require.NoError(t, validateHDFOutput(data))
}

func TestSystemCreate_FromSPDX3AIBOM_DatasetOnly(t *testing.T) {
	bomFile := bomFixturePath(t, "spdx-ai-dataset-1.json")
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", bomFile, "-o", outFile})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	byType := componentsByType(t, sys)
	assert.Empty(t, byType["aiModel"])
	require.Len(t, byType["dataset"], 1)
	require.NoError(t, validateHDFOutput(data))
}

// ---- --from format-assertion tests (system create) ----

func TestSystemCreate_FromFormat_MLBOMMatch(t *testing.T) {
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", bomFile, "--from", "cyclonedx-mlbom", "-o", outFile})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))
	c0 := sys["components"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "aiModel", c0["type"])
}

func TestSystemCreate_FromFormat_MLBOMMismatch(t *testing.T) {
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "--from", "cyclonedx-mlbom"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "detected as")
	assert.Contains(t, err.Error(), "cyclonedx-mlbom")
}

func TestSystemCreate_FromFormat_SPDXAIMatch(t *testing.T) {
	bomFile := bomFixturePath(t, "spdx-ai-model-1.json")
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", bomFile, "--from", "spdx-ai", "-o", outFile})
	require.NoError(t, cmd.Execute())
}

func TestSystemCreate_FromFormat_CycloneDXMatch(t *testing.T) {
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "--from", "cyclonedx", "-o", outFile})
	require.NoError(t, cmd.Execute())
}

func TestSystemCreate_FromFormat_CycloneDXRejectsMLBOM(t *testing.T) {
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", bomFile, "--from", "cyclonedx"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "detected as")
}

// --from spdx on a CycloneDX SBOM is a format mismatch (specific-format assertion).
func TestSystemCreate_FromFormat_SPDXMismatch(t *testing.T) {
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "--from", "spdx"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "detected as")
}

func TestSystemCreate_FromFormat_Unknown(t *testing.T) {
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "--from", "bogus"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown --from format")
	assert.Contains(t, err.Error(), "cyclonedx-mlbom")
}

// A URL input can't be fetched to verify its format, so --from must be rejected
// rather than blindly asserted (which could mislabel a remote BOM).
func TestSystemCreate_FromFormat_URLRejected(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "https://artifacts.example.com/sbom/webtier.cdx.json", "--from", "cyclonedx-mlbom", "--component-name", "WebTier"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "URL")
}

func TestSystemAddComponent(t *testing.T) {
	// Create initial system from results
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))
	sysFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile, "-o", sysFile})
	require.NoError(t, cmd.Execute())

	// Add component from SBOM
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/webgoat-sbom.json")
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"system", "add-component", sbomFile, "--system", sysFile, "--component-name", "WebGoat"})
	require.NoError(t, cmd2.Execute())

	data, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	components := sys["components"].([]interface{})
	assert.Len(t, components, 3) // 2 from results + 1 from SBOM
	last := components[2].(map[string]interface{})
	assert.Equal(t, "WebGoat", last["name"])
	boms := last["boms"].([]interface{})
	require.Len(t, boms, 1)
	assert.Equal(t, "cyclonedx", boms[0].(map[string]interface{})["format"])
}

func TestSystemAddComponent_RejectsDuplicate(t *testing.T) {
	// Create system with a component
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/juice-shop-sbom-minimal.json")
	sysFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "-o", sysFile})
	require.NoError(t, cmd.Execute())

	// Try adding same component name
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"system", "add-component", sbomFile, "--system", sysFile})
	err := cmd2.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestSystemUpdateComponent(t *testing.T) {
	// Create system with juice-shop component
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/juice-shop-sbom-minimal.json")
	sysFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "-o", sysFile})
	require.NoError(t, cmd.Execute())

	// Update with webgoat SBOM (different file, same component name)
	webgoatFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/webgoat-sbom.json")
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"system", "update-component", webgoatFile, "--system", sysFile, "--component-name", "juice-shop"})
	require.NoError(t, cmd2.Execute())

	data, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	components := sys["components"].([]interface{})
	assert.Len(t, components, 1) // still one component
	c0 := components[0].(map[string]interface{})
	boms := c0["boms"].([]interface{})
	require.Len(t, boms, 1)
	assert.Contains(t, boms[0].(map[string]interface{})["ref"], "webgoat-sbom.json") // updated ref
}

func TestSystemUpdateComponent_RejectsNonexistent(t *testing.T) {
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/juice-shop-sbom-minimal.json")
	sysFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "-o", sysFile})
	require.NoError(t, cmd.Execute())

	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"system", "update-component", sbomFile, "--system", sysFile, "--component-name", "DoesNotExist"})
	err := cmd2.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---- --generate-component-id flag tests ----

func TestSystemCreate_GenerateComponentId(t *testing.T) {
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))

	outFile := filepath.Join(t.TempDir(), "system.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile, "--generate-component-id", "-o", outFile})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	components := sys["components"].([]interface{})
	require.Len(t, components, 2)

	// Both components should have UUIDs
	c0 := components[0].(map[string]interface{})
	c1 := components[1].(map[string]interface{})
	id0, ok0 := c0["componentId"].(string)
	id1, ok1 := c1["componentId"].(string)
	assert.True(t, ok0, "first component should have componentId")
	assert.True(t, ok1, "second component should have componentId")
	assert.Len(t, id0, 36, "componentId should be UUID")
	assert.Len(t, id1, 36, "componentId should be UUID")
	assert.NotEqual(t, id0, id1, "each component should get a unique UUID")
}

func TestSystemCreate_GenerateComponentId_SBOM(t *testing.T) {
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/juice-shop-sbom-minimal.json")
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "--generate-component-id", "-o", outFile})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	components := sys["components"].([]interface{})
	c0 := components[0].(map[string]interface{})
	id, ok := c0["componentId"].(string)
	assert.True(t, ok, "SBOM component should have componentId")
	assert.Len(t, id, 36)
}

func TestSystemCreate_NoGenerateComponentId(t *testing.T) {
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))

	outFile := filepath.Join(t.TempDir(), "system.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile, "-o", outFile})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	// Without --generate-component-id, components from results without IDs
	// should not have componentId added
	components := sys["components"].([]interface{})
	c0 := components[0].(map[string]interface{})
	_, hasID := c0["componentId"]
	assert.False(t, hasID, "should not have componentId without --generate-component-id")
}

func TestSystemAddComponent_GenerateComponentId(t *testing.T) {
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))
	sysFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile, "-o", sysFile})
	require.NoError(t, cmd.Execute())

	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/webgoat-sbom.json")
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"system", "add-component", sbomFile, "--system", sysFile, "--component-name", "WebGoat", "--generate-component-id"})
	require.NoError(t, cmd2.Execute())

	data, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	components := sys["components"].([]interface{})
	last := components[len(components)-1].(map[string]interface{})
	id, ok := last["componentId"].(string)
	assert.True(t, ok, "added component should have componentId")
	assert.Len(t, id, 36)
}

// ---- --embed flag tests ----

func TestSystemCreate_FromSBOM_Embed(t *testing.T) {
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/juice-shop-sbom-minimal.json")
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "--embed", "-o", outFile})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	components := sys["components"].([]interface{})
	c0 := components[0].(map[string]interface{})

	boms := c0["boms"].([]interface{})
	require.Len(t, boms, 1)
	bom0 := boms[0].(map[string]interface{})

	// document should contain the full SBOM object
	doc, ok := bom0["document"].(map[string]interface{})
	require.True(t, ok, "expected document to be embedded object, got %T", bom0["document"])
	assert.Equal(t, "CycloneDX", doc["bomFormat"])

	// ref should still be present for traceability
	assert.Contains(t, bom0["ref"], "juice-shop-sbom-minimal.json")
}

func TestSystemCreate_FromSBOM_NoEmbed(t *testing.T) {
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/juice-shop-sbom-minimal.json")
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "-o", outFile})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	components := sys["components"].([]interface{})
	c0 := components[0].(map[string]interface{})

	boms := c0["boms"].([]interface{})
	require.Len(t, boms, 1)
	bom0 := boms[0].(map[string]interface{})

	// Without --embed, document should NOT be present
	assert.Nil(t, bom0["document"], "document should not be embedded without --embed")
	// ref should be present
	assert.Contains(t, bom0["ref"], "juice-shop-sbom-minimal.json")
}

func TestSystemAddComponent_Embed(t *testing.T) {
	// Create initial system from results
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))
	sysFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", resultsFile, "-o", sysFile})
	require.NoError(t, cmd.Execute())

	// Add component with --embed
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/webgoat-sbom.json")
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"system", "add-component", sbomFile, "--system", sysFile, "--component-name", "WebGoat", "--embed"})
	require.NoError(t, cmd2.Execute())

	data, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	components := sys["components"].([]interface{})
	last := components[len(components)-1].(map[string]interface{})
	assert.Equal(t, "WebGoat", last["name"])

	// document should be embedded
	boms := last["boms"].([]interface{})
	require.Len(t, boms, 1)
	doc, ok := boms[0].(map[string]interface{})["document"].(map[string]interface{})
	require.True(t, ok, "expected document to be embedded")
	assert.Equal(t, "CycloneDX", doc["bomFormat"])
}

func TestSystemUpdateComponent_Embed(t *testing.T) {
	// Create system with juice-shop
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/juice-shop-sbom-minimal.json")
	sysFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "-o", sysFile})
	require.NoError(t, cmd.Execute())

	// Update with --embed
	webgoatFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/webgoat-sbom.json")
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"system", "update-component", webgoatFile, "--system", sysFile, "--component-name", "juice-shop", "--embed"})
	require.NoError(t, cmd2.Execute())

	data, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	components := sys["components"].([]interface{})
	c0 := components[0].(map[string]interface{})

	// document should be the webgoat SBOM (not juice-shop)
	boms := c0["boms"].([]interface{})
	require.Len(t, boms, 1)
	bom0 := boms[0].(map[string]interface{})
	doc, ok := bom0["document"].(map[string]interface{})
	require.True(t, ok, "expected document to be embedded after update")
	assert.Contains(t, bom0["ref"], "webgoat-sbom.json")
	assert.NotNil(t, doc["bomFormat"])
}

func TestSystemCreate_TypeMapping(t *testing.T) {
	// As of v3.3.0, Component.type is a closed 11-value enum that matches
	// Target.type; the mapping in system_create.go is therefore identity for
	// all 11 known types. This test pins that contract.
	tests := []struct {
		targetType    string
		componentType string
	}{
		{"host", "host"},
		{"containerImage", "containerImage"},
		{"containerInstance", "containerInstance"},
		{"containerPlatform", "containerPlatform"},
		{"cloudAccount", "cloudAccount"},
		{"cloudResource", "cloudResource"},
		{"application", "application"},
		{"database", "database"},
		{"network", "network"},
		{"repository", "repository"},
		{"artifact", "artifact"},
	}

	for _, tt := range tests {
		t.Run(tt.targetType, func(t *testing.T) {
			resultsJSON := `{
				"baselines": [{"name": "B1", "checksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"}, "supports": [], "requirements": [], "groups": [], "depends": [], "inputs": []}],
				"components": [{"name": "target1", "type": "` + tt.targetType + `"}],
				"statistics": {"duration": 1},
				"generator": {"name": "test", "version": "1.0"}
			}`
			resultsFile := filepath.Join(t.TempDir(), "results.json")
			require.NoError(t, os.WriteFile(resultsFile, []byte(resultsJSON), 0o600))

			outFile := filepath.Join(t.TempDir(), "system.json")
			cmd := NewRootCmd()
			cmd.SetArgs([]string{"system", "create", resultsFile, "-o", outFile})

			err := cmd.Execute()
			require.NoError(t, err)

			data, err := os.ReadFile(outFile)
			require.NoError(t, err)

			var sys map[string]interface{}
			require.NoError(t, json.Unmarshal(data, &sys))

			components := sys["components"].([]interface{})
			c0 := components[0].(map[string]interface{})
			assert.Equal(t, tt.componentType, c0["type"], "target type %s should map to component type %s", tt.targetType, tt.componentType)
		})
	}
}
