package junit

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
	"github.com/stretchr/testify/assert"
)

func TestJunitFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "junit-to-hdf",
		Label:       "JUnit",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name: "detects testsuites root at confidence 1.0",
				Input: `<?xml version="1.0"?>
<testsuites name="AllTests" tests="10" failures="2">
  <testsuite name="Suite1" tests="5" failures="1">
    <testcase name="test1"/>
  </testsuite>
</testsuites>`,
				Confidence: 1.0,
			},
			{
				Name: "detects testsuite root at confidence 1.0",
				Input: `<?xml version="1.0"?>
<testsuite name="Suite1" tests="5" failures="1">
  <testcase name="test1"/>
</testsuite>`,
				Confidence: 1.0,
			},
			{
				// Checkov JUnit is still JUnit: it is warned about at conversion, never rerouted.
				Name: "still scores Checkov-shaped JUnit at confidence 1.0",
				Input: `<?xml version="1.0" ?>
<testsuites disabled="0" errors="0" failures="1" tests="1" time="0.0">
  <testsuite disabled="0" errors="0" failures="1" name="terraform scan" skipped="0" tests="1" time="0">
    <testcase name="[NONE][CKV_AWS_24] Ensure no security groups allow ingress from 0.0.0.0:0 to port 22" classname="/main.tf.aws_security_group.wide_open" file="/main.tf"/>
  </testsuite>
</testsuites>`,
				Confidence: 1.0,
			},
		},
		Negative: []fptest.DetectionCase{
			{
				Name: "does not match different XML format",
				Input: `<?xml version="1.0"?>
<FVDL xmlns="xmlns.fortify.com/schema/fvdl" version="1.12">
  <Build/>
</FVDL>`,
			},
			{Name: "does not match non-string input", Input: map[string]any{"testsuites": true}},
		},
	})
}

func TestIsCheckovTestCaseName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// Formats documented at https://www.checkov.io/8.Outputs/JUnit%20XML.html
		{"[NONE][CKV_AWS_24] Ensure no security groups allow ingress from 0.0.0.0:0 to port 22", true},
		{"[CRITICAL][CKV_AWS_20] S3 Bucket has an ACL defined which allows public READ access.", true},
		{"[LOW][CKV2_AWS_6] Ensure that S3 bucket has a Public Access block", true},
		{"[HIGH][CVE-2013-7370] connect: 2.6.0", true},
		{"[MEDIUM][CKV_AWS_18] a reworded description still matches", true},
		{"test_welcome_message", false},
		{"", false},
		{"[HIGH] only a severity bracket", false},
		{"[HIGH][TEST-1] a bracketed id that is not a Checkov or CVE id", false},
		{"CKV_AWS_24 is mentioned without the bracket prefix", false},
		{"prefix [NONE][CKV_AWS_24] not at the start", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isCheckovTestCaseName(tc.name))
		})
	}
}
