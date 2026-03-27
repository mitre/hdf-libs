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
	cmd.SetArgs([]string{"system", "create", "--from", resultsFile, "-o", outFile})

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
	assert.Equal(t, "compute", c0["type"]) // host -> compute

	// Check baselineRefs are set from baselines
	refs0, ok := c0["baselineRefs"].([]interface{})
	require.True(t, ok)
	assert.Len(t, refs0, 2) // both baselines referenced

	// Second component
	c1, ok := components[1].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "my-container", c1["name"])
	assert.Equal(t, "compute", c1["type"]) // containerImage -> compute

	// Interconnections should be empty array
	interconnections, ok := sys["interconnections"].([]interface{})
	require.True(t, ok)
	assert.Empty(t, interconnections)

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
	cmd.SetArgs([]string{"system", "create", "--from", resultsFile, "--name", "My Custom System", "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))
	assert.Equal(t, "My Custom System", sys["name"])
}

func TestSystemCreate_Stdout(t *testing.T) {
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", resultsFile})

	// Should succeed (output to stdout)
	err := cmd.Execute()
	require.NoError(t, err)
}

func TestSystemCreate_MissingFromFlag(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create"})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestSystemCreate_MissingFile(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", "/nonexistent/results.json"})

	err := cmd.Execute()
	assert.Error(t, err)
}

func TestSystemCreate_InvalidJSON(t *testing.T) {
	resultsFile := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte("not json"), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", resultsFile})

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
	cmd.SetArgs([]string{"system", "create", "--from", resultsFile})

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
	cmd.SetArgs([]string{"system", "create", "--from", resultsFile, "-o", outFile})

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
	cmd.SetArgs([]string{"system", "create", "--from", sbomFile, "-o", outFile})

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
	assert.Equal(t, "cyclonedx", c0["sbomFormat"])
	assert.Contains(t, c0["sbomRef"], "juice-shop-sbom-minimal.json")
	assert.Contains(t, c0["description"].(string), "19.1.1") // version extracted
}

func TestSystemCreate_FromSBOM_RequiresComponentNameWhenNoMetadata(t *testing.T) {
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/spdx-to-cyclonedx.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", sbomFile})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "component-name")
}

func TestSystemCreate_FromSBOM_WithExplicitComponentName(t *testing.T) {
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/spdx-to-cyclonedx.json")
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", sbomFile, "--component-name", "MyLib", "-o", outFile})

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
	cmd.SetArgs([]string{"system", "create", "--from", "https://example.com/sbom.cdx.json"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "component-name")
	assert.Contains(t, err.Error(), "URL")
}

func TestSystemCreate_FromURL_WithComponentName(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", "https://artifacts.example.com/sbom/webtier.cdx.json", "--component-name", "WebTier", "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))
	components := sys["components"].([]interface{})
	c0 := components[0].(map[string]interface{})
	assert.Equal(t, "WebTier", c0["name"])
	assert.Equal(t, "https://artifacts.example.com/sbom/webtier.cdx.json", c0["sbomRef"])
	assert.Equal(t, "cyclonedx", c0["sbomFormat"]) // guessed from .cdx.json
}

func TestSystemAddComponent(t *testing.T) {
	// Create initial system from results
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))
	sysFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", resultsFile, "-o", sysFile})
	require.NoError(t, cmd.Execute())

	// Add component from SBOM
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/webgoat-sbom.json")
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"system", "add-component", "--system", sysFile, "--from", sbomFile, "--component-name", "WebGoat"})
	require.NoError(t, cmd2.Execute())

	data, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	components := sys["components"].([]interface{})
	assert.Len(t, components, 3) // 2 from results + 1 from SBOM
	last := components[2].(map[string]interface{})
	assert.Equal(t, "WebGoat", last["name"])
	assert.Equal(t, "cyclonedx", last["sbomFormat"])
}

func TestSystemAddComponent_RejectsDuplicate(t *testing.T) {
	// Create system with a component
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/juice-shop-sbom-minimal.json")
	sysFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", sbomFile, "-o", sysFile})
	require.NoError(t, cmd.Execute())

	// Try adding same component name
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"system", "add-component", "--system", sysFile, "--from", sbomFile})
	err := cmd2.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestSystemUpdateComponent(t *testing.T) {
	// Create system with juice-shop component
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/juice-shop-sbom-minimal.json")
	sysFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", sbomFile, "-o", sysFile})
	require.NoError(t, cmd.Execute())

	// Update with webgoat SBOM (different file, same component name)
	webgoatFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/webgoat-sbom.json")
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"system", "update-component", "--system", sysFile, "--component-name", "juice-shop", "--from", webgoatFile})
	require.NoError(t, cmd2.Execute())

	data, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	components := sys["components"].([]interface{})
	assert.Len(t, components, 1) // still one component
	c0 := components[0].(map[string]interface{})
	assert.Contains(t, c0["sbomRef"], "webgoat-sbom.json") // updated ref
}

func TestSystemUpdateComponent_RejectsNonexistent(t *testing.T) {
	sbomFile := converterFixturePath(t, "cyclonedx-to-hdf", "input/juice-shop-sbom-minimal.json")
	sysFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", sbomFile, "-o", sysFile})
	require.NoError(t, cmd.Execute())

	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"system", "update-component", "--system", sysFile, "--component-name", "DoesNotExist", "--from", sbomFile})
	err := cmd2.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSystemCreate_TypeMapping(t *testing.T) {
	// Test various target type -> component type mappings
	tests := []struct {
		targetType    string
		componentType string
	}{
		{"host", "compute"},
		{"containerImage", "compute"},
		{"containerInstance", "compute"},
		{"containerPlatform", "compute"},
		{"cloudAccount", "other"},
		{"cloudResource", "other"},
		{"application", "application"},
		{"database", "database"},
		{"network", "network"},
		{"repository", "storage"},
		{"artifact", "storage"},
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
			cmd.SetArgs([]string{"system", "create", "--from", resultsFile, "-o", outFile})

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
