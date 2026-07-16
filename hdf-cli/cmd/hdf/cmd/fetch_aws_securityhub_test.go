package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchAWSSecurityHubCmd_Registered(t *testing.T) {
	root := NewRootCmd()
	fetch, _, err := root.Find([]string{"fetch", "aws-securityhub"})
	require.NoError(t, err)
	assert.Equal(t, "aws-securityhub", fetch.Name())
}

func TestFetchAWSSecurityHubCmd_RequiresRegion(t *testing.T) {
	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"aws-securityhub"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "region")
}

func TestFetchAWSSecurityHubCmd_InvalidRegion(t *testing.T) {
	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"aws-securityhub", "--region", "EVIL.attacker.com"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid region")
}

func TestFetchAWSSecurityHubCmd_InvalidFormat(t *testing.T) {
	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"aws-securityhub", "--region", "us-east-1", "--format", "bogus"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "format")
}

// TestFetchAWSSecurityHubCmd_CheckFlagWired confirms the --check flag is
// declared on the command. We don't execute the underlying call here
// because that would require AWS credentials; the flag-wired test is
// enough to catch a regression where the flag is renamed or removed.
func TestFetchAWSSecurityHubCmd_CheckFlagWired(t *testing.T) {
	root := NewRootCmd()
	fetch, _, err := root.Find([]string{"fetch", "aws-securityhub"})
	require.NoError(t, err)

	flag := fetch.Flags().Lookup("check")
	require.NotNil(t, flag, "--check flag must be declared on hdf fetch aws-securityhub")
	assert.Equal(t, "false", flag.DefValue, "--check should default to false")
}

func TestFetchAWSSecurityHubCmd_FilterJSONMissingFile(t *testing.T) {
	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"aws-securityhub", "--region", "us-east-1", "--filter-json", "/no/such/filter.json"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--filter-json")
}

func TestFetchAWSSecurityHubCmd_FilterJSONInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "filter.json")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"aws-securityhub", "--region", "us-east-1", "--filter-json", path})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --filter-json")
}
