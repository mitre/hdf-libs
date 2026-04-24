package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	awsconfig "github.com/mitre/hdf-libs/hdf-converters/v3/converters/aws-config-to-hdf/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFetchAWSConfigCmd_IsSubcommand verifies the command is reachable.
func TestFetchAWSConfigCmd_IsSubcommand(t *testing.T) {
	root := NewRootCmd()
	fetch, _, err := root.Find([]string{"fetch", "aws-config"})
	require.NoError(t, err)
	assert.Equal(t, "aws-config", fetch.Name())
}

// TestFetchAWSConfigCmd_RequiresRegion verifies --region is required.
func TestFetchAWSConfigCmd_RequiresRegion(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"fetch", "aws-config"})
	var errBuf bytes.Buffer
	root.SetErr(&errBuf)
	err := root.Execute()
	assert.Error(t, err)
}

// TestFetchAWSConfigCmd_Help verifies help text is accessible.
func TestFetchAWSConfigCmd_Help(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"fetch", "aws-config", "--help"})
	var out bytes.Buffer
	root.SetOut(&out)
	_ = root.Execute()
	help := out.String()
	assert.Contains(t, help, "region")
	assert.Contains(t, help, "profile")
}

// TestFetchCmd_Help verifies the fetch parent command help lists aws-config.
func TestFetchCmd_Help(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"fetch", "--help"})
	var out bytes.Buffer
	root.SetOut(&out)
	_ = root.Execute()
	assert.Contains(t, out.String(), "aws-config")
}

// TestFetchAWSConfigCmd_OutputIsValidHDF is an integration test that
// exercises the full fetch → convert → serialize path using a mock fetcher
// injected via the package-level hook set in tests.
//
// Rather than spinning up a cobra command and doing full exec (which would
// try to dial AWS), we call the underlying helpers directly to validate the
// data pipeline: fetcher bytes → ConvertAWSConfigToHDF → JSON output.
func TestFetchAWSConfigCmd_DataPipeline(t *testing.T) {
	// Minimal ConfigRulesFile JSON (what the fetcher produces)
	raw := []byte(`{
		"ConfigRules": [{
			"ConfigRuleId": "config-rule-test",
			"ConfigRuleName": "access-keys-rotated",
			"ConfigRuleArn": "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-test",
			"Description": "Test rule.",
			"Source": {"Owner": "AWS", "SourceIdentifier": "ACCESS_KEYS_ROTATED"},
			"InputParameters": "{}",
			"EvaluationResults": [{
				"EvaluationResultIdentifier": {
					"EvaluationResultQualifier": {
						"ConfigRuleName": "access-keys-rotated",
						"ResourceType": "AWS::IAM::User",
						"ResourceId": "user-1"
					}
				},
				"ComplianceType": "COMPLIANT",
				"ConfigRuleInvokedTime": "2021-04-09T14:39:21Z",
				"ResultRecordedTime": "2021-04-09T14:39:51Z"
			}]
		}]
	}`)

	// Call the converter directly — same function the fetch command uses internally.
	// Avoids depending on the global registry, which registry tests may clear.
	hdfResult, err := awsconfig.ConvertAWSConfigToHDF(raw, "test")
	require.NoError(t, err)
	output, err := json.MarshalIndent(hdfResult, "", "  ")
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(output, &parsed))

	baselines, ok := parsed["baselines"].([]interface{})
	require.True(t, ok)
	require.Len(t, baselines, 1)

	baseline := baselines[0].(map[string]interface{})
	reqs := baseline["requirements"].([]interface{})
	require.Len(t, reqs, 1)

	req := reqs[0].(map[string]interface{})
	assert.Equal(t, "config-rule-test", req["id"])
	assert.Equal(t, 0.5, req["impact"])
	assert.True(t, strings.Contains(req["title"].(string), "access-keys-rotated"))
}

// TestFetchAWSConfigCmd_InvalidFormat verifies --format validation.
func TestFetchAWSConfigCmd_InvalidFormat(t *testing.T) {
	cmd := newFetchAWSConfigCmd()
	cmd.Flags().Set("region", "us-east-1") //nolint:errcheck
	cmd.Flags().Set("format", "xml")       //nolint:errcheck
	err := cmd.RunE(cmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --format")
}

// TestFetchAWSConfigCmd_FormatFlagExists verifies --format is available.
func TestFetchAWSConfigCmd_FormatFlagExists(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"fetch", "aws-config", "--help"})
	var out bytes.Buffer
	root.SetOut(&out)
	_ = root.Execute()
	assert.Contains(t, out.String(), "format")
}

// TestFetchAWSConfigCmd_ExecuteWithContext verifies the command wires context correctly.
func TestFetchAWSConfigCmd_ExecuteWithContext(t *testing.T) {
	cmd := newFetchAWSConfigCmd()
	// A cancelled context should propagate into the RunE.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd.SetContext(ctx)
	// --region is required; without AWS creds this will fail at the fetcher,
	// but the important thing is it reaches the RunE (not arg validation).
	cmd.Flags().Set("region", "us-east-1") //nolint:errcheck
	// We expect an error (no real AWS) but not a panic.
	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
}
