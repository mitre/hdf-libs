//nolint:dupl
package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testBaseline = `{
	"name": "test-stig-profile",
	"title": "Test STIG Baseline",
	"version": "1.0.0",
	"summary": "A test baseline for CLI testing",
	"checksum": {"algorithm": "sha256", "value": "abc123"},
	"supports": [{"platform-name": "ubuntu"}],
	"groups": [],
	"requirements": [
		{
			"id": "SV-001",
			"title": "Ensure SSH is configured",
			"impact": 0.7,
			"descriptions": [
				{"label": "default", "data": "SSH must be properly configured."},
				{"label": "check", "data": "Verify SSH settings."},
				{"label": "fix", "data": "Update sshd_config."}
			],
			"tags": {
				"severity": "high",
				"nist": ["AC-17 (2)", "IA-5 (1)"],
				"cci": ["CCI-000068"]
			}
		},
		{
			"id": "SV-002",
			"title": "Ensure audit logging",
			"impact": 0.5,
			"descriptions": [
				{"label": "default", "data": "Audit logging must be enabled."}
			],
			"tags": {
				"severity": "medium",
				"nist": ["AU-3"]
			}
		}
	]
}`

func writeTestBaseline(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	require.NoError(t, os.WriteFile(path, []byte(testBaseline), 0o644))
	return path
}

func TestGenerateInSpecProfile_BasicUsage(t *testing.T) {
	inputPath := writeTestBaseline(t)
	outputDir := filepath.Join(t.TempDir(), "profile")

	_, stderr, err := executeCommand("generate", "inspec-profile", inputPath, outputDir)
	require.NoError(t, err)
	assert.Contains(t, stderr, "Generated InSpec profile")
	assert.Contains(t, stderr, "2 controls")

	// Verify inspec.yml exists and has expected content
	ymlBytes, err := os.ReadFile(filepath.Join(outputDir, "inspec.yml"))
	require.NoError(t, err)
	yml := string(ymlBytes)
	assert.Contains(t, yml, "name: test-stig-profile")
	assert.Contains(t, yml, "title: Test STIG Baseline")
	assert.Contains(t, yml, "inspec_version:")

	// Verify control files exist
	sv001, err := os.ReadFile(filepath.Join(outputDir, "controls", "SV-001.rb"))
	require.NoError(t, err)
	assert.Contains(t, string(sv001), "control 'SV-001' do")
	assert.Contains(t, string(sv001), "title 'Ensure SSH is configured'")
	assert.Contains(t, string(sv001), "impact 0.7")
	assert.Contains(t, string(sv001), "tag severity: 'high'")

	sv002, err := os.ReadFile(filepath.Join(outputDir, "controls", "SV-002.rb"))
	require.NoError(t, err)
	assert.Contains(t, string(sv002), "control 'SV-002' do")
}

func TestGenerateInSpecProfile_SingleFile(t *testing.T) {
	inputPath := writeTestBaseline(t)
	outputDir := filepath.Join(t.TempDir(), "profile")

	_, _, err := executeCommand("generate", "inspec-profile", inputPath, outputDir, "--single-file")
	require.NoError(t, err)

	// Should have single controls.rb with both controls
	content, err := os.ReadFile(filepath.Join(outputDir, "controls", "controls.rb"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "control 'SV-001' do")
	assert.Contains(t, string(content), "control 'SV-002' do")

	// Individual files should not exist
	_, err = os.Stat(filepath.Join(outputDir, "controls", "SV-001.rb"))
	assert.True(t, os.IsNotExist(err))
}

func TestGenerateInSpecProfile_MetadataOverrides(t *testing.T) {
	inputPath := writeTestBaseline(t)
	outputDir := filepath.Join(t.TempDir(), "profile")

	_, _, err := executeCommand("generate", "inspec-profile", inputPath, outputDir,
		"--maintainer", "MITRE SAF Team",
		"--license", "Apache-2.0",
		"--version", "2.0.0",
	)
	require.NoError(t, err)

	ymlBytes, err := os.ReadFile(filepath.Join(outputDir, "inspec.yml"))
	require.NoError(t, err)
	yml := string(ymlBytes)
	assert.Contains(t, yml, "maintainer: MITRE SAF Team")
	assert.Contains(t, yml, "license: Apache-2.0")
	assert.Contains(t, yml, "version: '2.0.0'")
}

func TestGenerateInSpecProfile_CustomInSpecVersion(t *testing.T) {
	inputPath := writeTestBaseline(t)
	outputDir := filepath.Join(t.TempDir(), "profile")

	_, _, err := executeCommand("generate", "inspec-profile", inputPath, outputDir,
		"--inspec-version", "~>5.0",
	)
	require.NoError(t, err)

	ymlBytes, err := os.ReadFile(filepath.Join(outputDir, "inspec.yml"))
	require.NoError(t, err)
	assert.Contains(t, string(ymlBytes), "inspec_version: '~>5.0'")
}

func TestGenerateInSpecProfile_MissingArgs(t *testing.T) {
	_, _, err := executeCommand("generate", "inspec-profile")
	assert.Error(t, err)
}

func TestGenerateInSpecProfile_InvalidInput(t *testing.T) {
	dir := t.TempDir()
	badFile := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(badFile, []byte(`{"not": "a baseline"}`), 0o644))

	_, _, err := executeCommand("generate", "inspec-profile", badFile, filepath.Join(dir, "out"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "schema validation failed")
}

func TestGenerateInSpecProfile_FileNotFound(t *testing.T) {
	_, _, err := executeCommand("generate", "inspec-profile", "/nonexistent/file.json", t.TempDir())
	assert.Error(t, err)
}

func TestGenerateCmd_Help(t *testing.T) {
	_, stderr, err := executeCommand("generate", "--help")
	assert.NoError(t, err)
	_ = stderr // help goes to stdout
}
