package awsconfig

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// revMixInput mixes secretsmanager-rotation-enabled-check (sole control
// AC-3(15) has no Rev 4 equivalent — the genuine mismatch that survives the
// crosswalk backfill; its Rev 4 row is an explicit empty-NIST-ID marker) with
// cloudtrail-enabled (mapped at both revisions).
const revMixInput = `{"ConfigRules":[
 {"ConfigRuleId":"r1","ConfigRuleName":"secretsmanager-rotation-enabled-check","ConfigRuleArn":"arn:aws:config:us-east-1:123456789012:config-rule/r1","Source":{"Owner":"AWS","SourceIdentifier":"SECRETSMANAGER_ROTATION_ENABLED_CHECK"},"EvaluationResults":[{"EvaluationResultIdentifier":{"EvaluationResultQualifier":{"ConfigRuleName":"secretsmanager-rotation-enabled-check","ResourceType":"AWS::SecretsManager::Secret","ResourceId":"s1"}},"ComplianceType":"NON_COMPLIANT","ResultRecordedTime":"2024-02-19T00:00:05Z","ConfigRuleInvokedTime":"2024-02-19T00:00:05Z"}]},
 {"ConfigRuleId":"r2","ConfigRuleName":"cloudtrail-enabled","ConfigRuleArn":"arn:aws:config:us-east-1:123456789012:config-rule/r2","Source":{"Owner":"AWS","SourceIdentifier":"CLOUD_TRAIL_ENABLED"},"EvaluationResults":[{"EvaluationResultIdentifier":{"EvaluationResultQualifier":{"ConfigRuleName":"cloudtrail-enabled","ResourceType":"AWS::CloudTrail::Trail","ResourceId":"t1"}},"ComplianceType":"COMPLIANT","ResultRecordedTime":"2024-02-19T00:00:06Z","ConfigRuleInvokedTime":"2024-02-19T00:00:06Z"}]}
]}`

func TestRevisionAlignment_WarnsOnMismatch(t *testing.T) {
	require.NoError(t, nist.SetRevision(4))
	defer nist.ResetRevision()

	var buf bytes.Buffer
	prevOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prevOutput)

	_, err := ConvertAWSConfigToHDF([]byte(revMixInput), converterVersion)
	require.NoError(t, err, "a revision mismatch must not fail conversion outside strict mode")

	out := buf.String()
	assert.Contains(t, out, "WARNING")
	assert.Contains(t, out, "secretsmanager-rotation-enabled-check")
	assert.Contains(t, out, "Rev 5")
	// cloudtrail-enabled is mapped at Rev 4, so it must not be flagged.
	assert.NotContains(t, out, "cloudtrail-enabled")
}

func TestRevisionAlignment_StrictErrors(t *testing.T) {
	require.NoError(t, nist.SetRevision(4))
	nist.SetStrict(true)
	defer func() {
		nist.ResetRevision()
		nist.SetStrict(false)
	}()

	_, err := ConvertAWSConfigToHDF([]byte(revMixInput), converterVersion)
	require.Error(t, err, "strict mode must fail when a rule is mapped only at another revision")
	assert.Contains(t, err.Error(), "secretsmanager-rotation-enabled-check")
	assert.Contains(t, err.Error(), "--nist-rev")
}

func TestRevisionAlignment_NoWarningWhenAligned(t *testing.T) {
	require.NoError(t, nist.SetRevision(5))
	defer nist.ResetRevision()

	var buf bytes.Buffer
	prevOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prevOutput)

	_, err := ConvertAWSConfigToHDF([]byte(revMixInput), converterVersion)
	require.NoError(t, err)
	assert.NotContains(t, strings.ToUpper(buf.String()), "WARNING")
}
