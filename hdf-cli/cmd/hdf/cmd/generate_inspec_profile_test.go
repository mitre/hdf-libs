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

func TestGenerateInSpecProfile_XccdfBenchmarkInput(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "..",
		"hdf-converters", "converters", "xccdf-results-to-hdf",
		"fixtures", "input", "benchmark-minimal-1.2.xml")
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		t.Skip("XCCDF benchmark fixture not found (LFS not pulled?)")
	}

	outputDir := filepath.Join(t.TempDir(), "profile")
	_, stderr, err := executeCommand("generate", "inspec-profile", fixturePath, outputDir)
	require.NoError(t, err)
	assert.Contains(t, stderr, "Generated InSpec profile")
	assert.Contains(t, stderr, "3 controls")

	// Verify inspec.yml has benchmark-derived metadata
	ymlBytes, err := os.ReadFile(filepath.Join(outputDir, "inspec.yml"))
	require.NoError(t, err)
	yml := string(ymlBytes)
	assert.Contains(t, yml, "name: ms-windows-server-2022-stig")
	assert.Contains(t, yml, "Microsoft Windows Server 2022")

	// Verify control files generated from XCCDF rules
	ctrl, err := os.ReadFile(filepath.Join(outputDir, "controls", "SV-254238.rb"))
	require.NoError(t, err)
	assert.Contains(t, string(ctrl), "control 'SV-254238' do")
}

func TestGenerateInSpecProfile_XccdfFullSTIG(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "..",
		"hdf-generators", "test", "fixtures", "stig-rhel9-benchmark.xml")
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		t.Skip("RHEL9 STIG benchmark fixture not found (LFS not pulled?)")
	}

	outputDir := filepath.Join(t.TempDir(), "profile")
	_, stderr, err := executeCommand("generate", "inspec-profile", fixturePath, outputDir)
	require.NoError(t, err)
	assert.Contains(t, stderr, "Generated InSpec profile")
	assert.Contains(t, stderr, "452 controls")

	// Verify inspec.yml has RHEL9 STIG metadata
	ymlBytes, err := os.ReadFile(filepath.Join(outputDir, "inspec.yml"))
	require.NoError(t, err)
	yml := string(ymlBytes)
	assert.Contains(t, yml, "name: rhel-9-stig")
	assert.Contains(t, yml, "Red Hat Enterprise Linux 9")

	// Spot-check a known RHEL9 STIG control
	ctrl, err := os.ReadFile(filepath.Join(outputDir, "controls", "SV-257777.rb"))
	require.NoError(t, err)
	content := string(ctrl)
	assert.Contains(t, content, "control 'SV-257777' do")
	assert.Contains(t, content, "impact")
	assert.Contains(t, content, "tag nist:")

	// Verify control count matches groups in the STIG
	entries, err := os.ReadDir(filepath.Join(outputDir, "controls"))
	require.NoError(t, err)
	assert.Equal(t, 452, len(entries))
}

func TestGenerateInSpecProfile_XccdfAutoDetect(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "..",
		"hdf-converters", "converters", "xccdf-results-to-hdf",
		"fixtures", "input", "benchmark-minimal-1.2.xml")
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		t.Skip("XCCDF benchmark fixture not found (LFS not pulled?)")
	}

	// Auto-detection: XML file without --source-type should auto-detect as XCCDF
	outputDir := filepath.Join(t.TempDir(), "profile")
	_, _, err := executeCommand("generate", "inspec-profile", fixturePath, outputDir)
	require.NoError(t, err)

	// Should have generated control files
	_, err = os.Stat(filepath.Join(outputDir, "controls", "SV-254238.rb"))
	assert.NoError(t, err)
}

func TestGenerateInSpecProfile_ExplicitSourceTypeXccdf(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "..",
		"hdf-converters", "converters", "xccdf-results-to-hdf",
		"fixtures", "input", "benchmark-minimal-1.2.xml")
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		t.Skip("XCCDF benchmark fixture not found (LFS not pulled?)")
	}

	outputDir := filepath.Join(t.TempDir(), "profile")
	_, _, err := executeCommand("generate", "inspec-profile", fixturePath, outputDir, "--source-type", "xccdf")
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(outputDir, "controls", "SV-254238.rb"))
	assert.NoError(t, err)
}

func TestGenerateInSpecProfile_ExplicitSourceTypeBaseline(t *testing.T) {
	// Explicit --source-type baseline should still work for JSON input
	inputPath := writeTestBaseline(t)
	outputDir := filepath.Join(t.TempDir(), "profile")

	_, _, err := executeCommand("generate", "inspec-profile", inputPath, outputDir, "--source-type", "baseline")
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(outputDir, "controls", "SV-001.rb"))
	assert.NoError(t, err)
}

func TestGenerateInSpecProfile_XccdfResultsError(t *testing.T) {
	// XCCDF file with TestResult should produce a clear error when used as generate input
	fixturePath := filepath.Join("..", "..", "..", "..",
		"hdf-converters", "converters", "xccdf-results-to-hdf",
		"fixtures", "input", "minimal.xml")
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		t.Skip("XCCDF results fixture not found (LFS not pulled?)")
	}

	outputDir := filepath.Join(t.TempDir(), "profile")
	_, _, err := executeCommand("generate", "inspec-profile", fixturePath, outputDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "results document")
}

func TestGenerateInSpecProfile_InvalidXML(t *testing.T) {
	dir := t.TempDir()
	badXML := filepath.Join(dir, "bad.xml")
	require.NoError(t, os.WriteFile(badXML, []byte(`<not-xccdf>garbage</not-xccdf>`), 0o644))

	outputDir := filepath.Join(dir, "out")
	_, _, err := executeCommand("generate", "inspec-profile", badXML, outputDir, "--source-type", "xccdf")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an XCCDF Benchmark")
}

func TestGenerateInSpecProfile_CannotAutoDetect(t *testing.T) {
	dir := t.TempDir()
	weirdFile := filepath.Join(dir, "weird.txt")
	require.NoError(t, os.WriteFile(weirdFile, []byte(`neither json nor xml`), 0o644))

	outputDir := filepath.Join(dir, "out")
	_, _, err := executeCommand("generate", "inspec-profile", weirdFile, outputDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot auto-detect")
}

func TestGenerateCmd_Help(t *testing.T) {
	_, stderr, err := executeCommand("generate", "--help")
	assert.NoError(t, err)
	_ = stderr // help goes to stdout
}
