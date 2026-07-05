package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createBaseSystem writes a system document with a single "juice-shop"
// component (imported from the plain CycloneDX SBOM fixture) and returns its
// path. Used as the target for add-component / update-component tests.
func createBaseSystem(t *testing.T) string {
	t.Helper()
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")
	sysFile := filepath.Join(t.TempDir(), "system.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", sbomFile, "-o", sysFile})
	require.NoError(t, cmd.Execute())
	return sysFile
}

// ---- add-component --from format-assertion tests ----

// add-component/update-component do not yet ingest AI-BOMs — they model every BOM
// as an SBOM component, so an AI-BOM is rejected with a redirect to `hdf system
// create` rather than mislabeled (generalization tracked in hdf-libs-opk1).
func TestSystemAddComponent_MLBOMRejected(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFile, "--system", sysFile, "--from", "cyclonedx-mlbom", "--component-name", "Model"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "system create")
}

// Auto-detected AI-BOM (no --from) is also rejected, never silently ingested.
func TestSystemAddComponent_MLBOMRejected_AutoDetect(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFile, "--system", sysFile, "--component-name", "Model"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "system create")
}

func TestSystemAddComponent_FromFormat_MLBOMMismatch(t *testing.T) {
	sysFile := createBaseSystem(t)
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", sbomFile, "--system", sysFile, "--from", "cyclonedx-mlbom", "--component-name", "Other"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "detected as")
}

func TestSystemAddComponent_SPDXAIRejected(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "spdx-ai-model-1.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFile, "--system", sysFile, "--from", "spdx-ai", "--component-name", "Dataset"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "system create")
}

func TestSystemAddComponent_FromFormat_CycloneDXMatch(t *testing.T) {
	sysFile := createBaseSystem(t)
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", sbomFile, "--system", sysFile, "--from", "cyclonedx", "--component-name", "SecondTier"})
	require.NoError(t, cmd.Execute())
}

func TestSystemAddComponent_FromFormat_CycloneDXRejectsMLBOM(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", bomFile, "--system", sysFile, "--from", "cyclonedx", "--component-name", "Model"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "detected as")
}

func TestSystemAddComponent_FromFormat_Unknown(t *testing.T) {
	sysFile := createBaseSystem(t)
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", sbomFile, "--system", sysFile, "--from", "bogus", "--component-name", "X"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown --from format")
}

func TestSystemAddComponent_MissingPositional(t *testing.T) {
	sysFile := createBaseSystem(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", "--system", sysFile, "--component-name", "X"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "arg")
}

func TestSystemAddComponent_URLPositional(t *testing.T) {
	sysFile := createBaseSystem(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", "https://artifacts.example.com/sbom/auth.cdx.json", "--system", sysFile, "--component-name", "AuthService"})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "auth.cdx.json")
}

// A URL input can't be fetched to verify its format, so --from is rejected.
func TestSystemAddComponent_FromFormat_URLRejected(t *testing.T) {
	sysFile := createBaseSystem(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", "https://artifacts.example.com/sbom/auth.cdx.json", "--system", sysFile, "--from", "cyclonedx-mlbom", "--component-name", "AuthService"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "URL")
}

// loadBOM must reject oversized input via the size gate before json.Unmarshal.
func TestSystemAddComponent_OversizedInputRejected(t *testing.T) {
	sysFile := createBaseSystem(t)
	big := make([]byte, 2*1024*1024)
	for i := range big {
		big[i] = 'a'
	}
	f := filepath.Join(t.TempDir(), "big.json")
	require.NoError(t, os.WriteFile(f, big, 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "add-component", f, "--system", sysFile, "--component-name", "X", "--max-size", "1"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum allowed size")
}

// ---- update-component --from format-assertion tests ----

func TestSystemUpdateComponent_MLBOMRejected(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", bomFile, "--system", sysFile, "--component-name", "juice-shop", "--from", "cyclonedx-mlbom"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "system create")
}

func TestSystemUpdateComponent_MLBOMRejected_AutoDetect(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", bomFile, "--system", sysFile, "--component-name", "juice-shop"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "system create")
}

func TestSystemUpdateComponent_FromFormat_MLBOMMismatch(t *testing.T) {
	sysFile := createBaseSystem(t)
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", sbomFile, "--system", sysFile, "--component-name", "juice-shop", "--from", "cyclonedx-mlbom"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "detected as")
}

func TestSystemUpdateComponent_SPDXAIRejected(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "spdx-ai-model-1.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", bomFile, "--system", sysFile, "--component-name", "juice-shop", "--from", "spdx-ai"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "system create")
}

func TestSystemUpdateComponent_FromFormat_SPDXMatch(t *testing.T) {
	sysFile := createBaseSystem(t)
	sbomFile := bomFixturePath(t, "spdx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", sbomFile, "--system", sysFile, "--component-name", "juice-shop", "--from", "spdx"})
	require.NoError(t, cmd.Execute())
}

func TestSystemUpdateComponent_FromFormat_CycloneDXRejectsMLBOM(t *testing.T) {
	sysFile := createBaseSystem(t)
	bomFile := bomFixturePath(t, "cyclonedx-mlbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", bomFile, "--system", sysFile, "--component-name", "juice-shop", "--from", "cyclonedx"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "detected as")
}

func TestSystemUpdateComponent_FromFormat_Unknown(t *testing.T) {
	sysFile := createBaseSystem(t)
	sbomFile := bomFixturePath(t, "cyclonedx-sbom.json")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", sbomFile, "--system", sysFile, "--component-name", "juice-shop", "--from", "bogus"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown --from format")
}

func TestSystemUpdateComponent_MissingPositional(t *testing.T) {
	sysFile := createBaseSystem(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", "--system", sysFile, "--component-name", "juice-shop"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "arg")
}

func TestSystemUpdateComponent_URLPositional(t *testing.T) {
	sysFile := createBaseSystem(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "update-component", "https://artifacts.example.com/sbom/juice.cdx.json", "--system", sysFile, "--component-name", "juice-shop"})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(sysFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "juice.cdx.json")
}
