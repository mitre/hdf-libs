package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// convertAWSConfigFixture runs `hdf convert` on the aws-config multi-rule
// fixture with the given extra flags and returns the HDF output.
func convertAWSConfigFixture(t *testing.T, extraArgs ...string) string {
	t.Helper()
	input := converterFixturePath(t, "aws-config-to-hdf", "input/multi-rule.json")
	out := filepath.Join(t.TempDir(), "out.json")

	args := append([]string{"convert", "--from", "aws-config", "--to", "hdf", input, "-o", out}, extraArgs...)
	cmd := NewRootCmd()
	cmd.SetArgs(args)
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	return string(data)
}

// Across the multi-rule fixture, AC-2(j) is emitted only at Rev 4 and AC-3(15)
// only at Rev 5, so each tag cleanly discriminates which catalog was emitted.
func TestConvertNISTRevDefault(t *testing.T) {
	out := convertAWSConfigFixture(t)
	assert.Contains(t, out, "AC-3(15)", "default conversion should emit Rev 5 tags")
	assert.NotContains(t, out, "AC-2(j)", "default conversion must not emit Rev 4-only tags")
}

func TestConvertNISTRev5(t *testing.T) {
	out := convertAWSConfigFixture(t, "--nist-rev", "5")
	assert.Contains(t, out, "AC-3(15)", "--nist-rev 5 should emit Rev 5 tags")
	assert.NotContains(t, out, "AC-2(j)", "--nist-rev 5 must not emit Rev 4-only tags")
}

func TestConvertNISTRev4Explicit(t *testing.T) {
	out := convertAWSConfigFixture(t, "--nist-rev", "4")
	assert.Contains(t, out, "AC-2(j)")
	assert.NotContains(t, out, "AC-3(15)")
}

func TestConvertNISTRevUnsupported(t *testing.T) {
	input := converterFixturePath(t, "aws-config-to-hdf", "input/multi-rule.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "aws-config", "--to", "hdf", input, "--nist-rev", "99"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported NIST revision 99")
}

// revMixFixture writes an aws-config input mixing api-gw-ssl-enabled (mapped
// only at Rev 5) with cloudtrail-enabled (mapped at both revisions).
func revMixFixture(t *testing.T) string {
	t.Helper()
	const doc = `{"ConfigRules":[
 {"ConfigRuleId":"r1","ConfigRuleName":"api-gw-ssl-enabled","ConfigRuleArn":"arn:aws:config:us-east-1:123456789012:config-rule/r1","Source":{"Owner":"AWS","SourceIdentifier":"API_GW_SSL_ENABLED"},"EvaluationResults":[{"EvaluationResultIdentifier":{"EvaluationResultQualifier":{"ConfigRuleName":"api-gw-ssl-enabled","ResourceType":"AWS::ApiGateway::Stage","ResourceId":"s1"}},"ComplianceType":"NON_COMPLIANT","ResultRecordedTime":"2024-02-19T00:00:05Z","ConfigRuleInvokedTime":"2024-02-19T00:00:05Z"}]}
]}`
	p := filepath.Join(t.TempDir(), "revmix.json")
	require.NoError(t, os.WriteFile(p, []byte(doc), 0o600))
	return p
}

// TestConvertNISTStrictErrors verifies --nist-strict turns a revision mismatch
// (a Rev5-only rule converted at Rev 4) into a hard error.
func TestConvertNISTStrictErrors(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "aws-config", "--nist-rev", "4", "--nist-strict", revMixFixture(t)})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api-gw-ssl-enabled")
}

// TestConvertNISTStrictPassesWhenAligned verifies --nist-strict succeeds when
// every rule is mapped at the requested revision.
func TestConvertNISTStrictPassesWhenAligned(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"convert", "--from", "aws-config", "--nist-rev", "5", "--nist-strict", revMixFixture(t), "-o", out})
	require.NoError(t, cmd.Execute())
}

// TestConvertNISTRevNoLeak verifies the revision selection is reset after a
// conversion, so a Rev 5 run does not bleed into a subsequent default run.
func TestConvertNISTRevNoLeak(t *testing.T) {
	rev4 := convertAWSConfigFixture(t, "--nist-rev", "4")
	assert.Contains(t, rev4, "AC-2(j)")

	deflt := convertAWSConfigFixture(t)
	assert.Contains(t, deflt, "AC-3(15)", "default run after a Rev 4 run should be back to Rev 5")
	assert.NotContains(t, deflt, "AC-2(j)", "Rev 4 selection leaked into a later default run")
}
