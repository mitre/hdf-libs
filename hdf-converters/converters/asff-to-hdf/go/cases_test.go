package asff

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- whichSpecialCase ----

func TestWhichSpecialCase(t *testing.T) {
	cases := []struct {
		name     string
		arn      string
		wantCase specialCase
	}{
		{"securityhub", "arn:aws:securityhub:us-east-1::product/aws/securityhub", caseSecurityHub},
		{"prowler-not-yet", "arn:aws:securityhub:us-east-1::product/prowler/prowler", caseDefault},
		{"trivy-not-yet", "arn:aws:securityhub:us-east-1::product/aquasecurity/aquasecurity", caseDefault},
		{"missing", "", caseDefault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := whichSpecialCase(map[string]any{"ProductArn": tc.arn})
			assert.Equal(t, tc.wantCase, got)
		})
	}
}

func TestDispatch_NonSecurityHubReturnsDefault(t *testing.T) {
	f := map[string]any{"ProductArn": "arn:aws:securityhub:us-east-1::product/prowler/prowler"}
	h := dispatch(f)
	_, ok := h.(defaultCase)
	assert.True(t, ok, "non-securityhub ARN → defaultCase")
}

func TestDispatchAll_EmptyReturnsDefault(t *testing.T) {
	h := dispatchAll(nil)
	_, ok := h.(defaultCase)
	assert.True(t, ok)
}

func TestDispatchAll_DefaultArn(t *testing.T) {
	h := dispatchAll([]map[string]any{{"ProductArn": "arn:aws:securityhub:us-east-1::product/unknown/unknown"}})
	_, ok := h.(defaultCase)
	assert.True(t, ok)
}

// ---- defaultCase direct ----

func TestDefaultCase_ProductName(t *testing.T) {
	t.Run("trailing product info", func(t *testing.T) {
		got := defaultCase{}.productName([]map[string]any{
			{"ProductArn": "arn:aws:securityhub:us-east-1::product/companyx/scannery"},
		})
		assert.Equal(t, "companyx - scannery", got)
	})
	t.Run("empty list", func(t *testing.T) {
		got := defaultCase{}.productName(nil)
		assert.Equal(t, "ASFF Findings", got)
	})
	t.Run("malformed arn", func(t *testing.T) {
		got := defaultCase{}.productName([]map[string]any{{"ProductArn": "garbage"}})
		assert.Equal(t, "ASFF Findings", got)
	})
}

func TestDefaultCase_FindingID(t *testing.T) {
	got := defaultCase{}.findingID(map[string]any{"GeneratorId": "rule-42"})
	assert.Equal(t, "rule-42", got)
}

func TestDefaultCase_FindingImpact(t *testing.T) {
	cases := []struct {
		name    string
		finding map[string]any
		want    float64
	}{
		{"critical label", map[string]any{"Severity": map[string]any{"Label": "CRITICAL"}}, 0.9},
		{"high label", map[string]any{"Severity": map[string]any{"Label": "HIGH"}}, 0.7},
		{"normalized fallback (float)", map[string]any{"Severity": map[string]any{"Normalized": 45.0}}, 0.45},
		{"suppressed overrides label", map[string]any{
			"Severity": map[string]any{"Label": "CRITICAL"},
			"Workflow": map[string]any{"Status": "SUPPRESSED"},
		}, 0.0},
		{"missing severity", map[string]any{}, 0.0},
		{"unknown label no normalized", map[string]any{"Severity": map[string]any{"Label": "BOGUS"}}, 0.0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, handled := defaultCase{}.findingImpact(tc.finding)
			assert.True(t, handled)
			assert.InDelta(t, tc.want, got, 0.001)
		})
	}
}

func TestDefaultCase_FindingNISTTags(t *testing.T) {
	got := defaultCase{}.findingNISTTags(map[string]any{})
	assert.Empty(t, got)
}

func TestDefaultCase_FindingStatus_ErrorBranch(t *testing.T) {
	got, _ := defaultCase{}.findingStatus(map[string]any{"Compliance": map[string]any{"Status": "BOGUS"}})
	assert.Equal(t, hdf.Error, got)
}

// ---- securityHubCase direct ----

func TestSecurityHubCase_FindingID(t *testing.T) {
	t.Run("prefers ControlId", func(t *testing.T) {
		f := map[string]any{
			"ProductFields": map[string]any{
				"ControlId": "CTRL-100",
				"RuleId":    "1.1",
			},
			"GeneratorId": "should-not-be-used",
		}
		assert.Equal(t, "CTRL-100", securityHubCase{}.findingID(f))
	})
	t.Run("falls back to RuleId", func(t *testing.T) {
		f := map[string]any{
			"ProductFields": map[string]any{"RuleId": "1.1"},
			"GeneratorId":   "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.1",
		}
		assert.Equal(t, "1.1", securityHubCase{}.findingID(f))
	})
	t.Run("falls back to GeneratorId tail", func(t *testing.T) {
		f := map[string]any{"GeneratorId": "arn:aws:.../rule/9.9"}
		assert.Equal(t, "9.9", securityHubCase{}.findingID(f))
	})
	t.Run("plain GeneratorId no slash", func(t *testing.T) {
		f := map[string]any{"GeneratorId": "plain"}
		assert.Equal(t, "plain", securityHubCase{}.findingID(f))
	})
}

func TestSecurityHubCase_ProductName(t *testing.T) {
	t.Run("missing StandardsControlArn falls back to default", func(t *testing.T) {
		f := []map[string]any{{"ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub"}}
		got := securityHubCase{}.productName(f)
		// Falls through to defaultCase.productName → tail split.
		assert.Equal(t, "aws - securityhub", got)
	})
	t.Run("short arn falls back to default", func(t *testing.T) {
		f := []map[string]any{{
			"ProductArn":    "arn:aws:securityhub:us-east-1::product/aws/securityhub",
			"ProductFields": map[string]any{"StandardsControlArn": "short"},
		}}
		got := securityHubCase{}.productName(f)
		assert.Equal(t, "aws - securityhub", got)
	})
	t.Run("empty findings", func(t *testing.T) {
		got := securityHubCase{}.productName(nil)
		assert.Equal(t, "AWS Security Hub", got)
	})
}

func TestSecurityHubCase_FindingImpact_HighNotBumped(t *testing.T) {
	f := map[string]any{
		"ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
		"Severity":   map[string]any{"Label": "HIGH"},
	}
	got, _ := securityHubCase{}.findingImpact(f)
	assert.InDelta(t, 0.7, got, 0.001)
}

func TestSecurityHubCase_FindingImpact_SuppressedOverridesLabel(t *testing.T) {
	f := map[string]any{
		"Severity": map[string]any{"Label": "CRITICAL"},
		"Workflow": map[string]any{"Status": "SUPPRESSED"},
	}
	got, _ := securityHubCase{}.findingImpact(f)
	assert.InDelta(t, 0.0, got, 0.001)
}

func TestSecurityHubCase_FindingImpact_MissingSeverity(t *testing.T) {
	got, _ := securityHubCase{}.findingImpact(map[string]any{})
	assert.InDelta(t, 0.0, got, 0.001)
}

func TestSecurityHubCase_FindingImpact_NormalizedFallback(t *testing.T) {
	f := map[string]any{"Severity": map[string]any{"Normalized": 80}}
	got, _ := securityHubCase{}.findingImpact(f)
	assert.InDelta(t, 0.8, got, 0.001)
}

func TestSecurityHubCase_FindingNISTTags_NonConfigRule(t *testing.T) {
	got := securityHubCase{}.findingNISTTags(map[string]any{"ProductFields": map[string]any{}})
	assert.Empty(t, got)
}

func TestSecurityHubCase_FindingNISTTags_UnknownRule(t *testing.T) {
	got := securityHubCase{}.findingNISTTags(map[string]any{
		"ProductFields": map[string]any{
			"RelatedAWSResources:0/type": "AWS::Config::ConfigRule",
			"RelatedAWSResources:0/name": "this-rule-does-not-exist-in-the-mapping",
		},
	})
	assert.Empty(t, got)
}

// ---- helpers ----

func TestTitleCase(t *testing.T) {
	assert.Equal(t, "Cis Aws Foundations", titleCase("cis aws foundations"))
	assert.Equal(t, "", titleCase(""))
}

func TestGetString_MissingPath(t *testing.T) {
	_, ok := getString(map[string]any{"a": map[string]any{"b": "c"}}, "a.x")
	assert.False(t, ok)
}

func TestGetString_NilMap(t *testing.T) {
	_, ok := getString(nil, "a")
	assert.False(t, ok)
}

func TestGetString_NoDot(t *testing.T) {
	v, ok := getString(map[string]any{"a": "b"}, "a")
	require.True(t, ok)
	assert.Equal(t, "b", v)
}

// ---- merge helpers ----

func TestMergeDescriptions_Dedupes(t *testing.T) {
	a := []hdf.Description{{Label: "default", Data: "x"}, {Label: "fix", Data: "y"}}
	b := []hdf.Description{{Label: "default", Data: "x"}, {Label: "fix", Data: "z"}}
	out := mergeDescriptions(a, b)
	assert.Len(t, out, 3)
}

func TestMergeRefs_DedupesByURL(t *testing.T) {
	u1 := "https://a.example.com"
	u2 := "https://b.example.com"
	a := []hdf.Reference{{URL: &u1}}
	b := []hdf.Reference{{URL: &u1}, {URL: &u2}, {URL: nil}}
	out := mergeRefs(a, b)
	assert.Len(t, out, 2)
}

func TestMergeTags(t *testing.T) {
	a := map[string]any{"nist": []string{"AC-2", "AC-3"}}
	b := map[string]any{"nist": []string{"AC-2", "AC-4"}, "cci": []string{"CCI-100"}}
	out := mergeTags(a, b)
	assert.ElementsMatch(t, []string{"AC-2", "AC-3", "AC-4"}, out["nist"])
	assert.Equal(t, []string{"CCI-100"}, out["cci"])
}

func TestMergeTags_NilHandling(t *testing.T) {
	assert.NotNil(t, mergeTags(nil, map[string]any{"x": "y"}))
	assert.NotNil(t, mergeTags(map[string]any{"x": "y"}, nil))
}

// ---- parsing edge cases ----

func TestParseFindings_NonArrayFindings(t *testing.T) {
	_, err := parseFindings([]byte(`{"Findings": "not an array"}`))
	require.Error(t, err)
}

func TestParseFindings_FindingsContainsNonObject(t *testing.T) {
	_, err := parseFindings([]byte(`{"Findings": ["string", 42]}`))
	require.Error(t, err)
}

func TestParseFindings_GarbageTopLevel(t *testing.T) {
	_, err := parseFindings([]byte(`42`))
	require.Error(t, err)
}

// ---- converter-level: hits a non-securityhub ARN through the full pipeline ----

func TestConvert_DefaultArn_FullPath(t *testing.T) {
	input := []byte(`{"Findings": [{
		"SchemaVersion": "2018-10-08",
		"Id": "default-test",
		"ProductArn": "arn:aws:securityhub:us-east-1::product/companyx/scannery",
		"GeneratorId": "scannery/rule/123",
		"AwsAccountId": "999999999999",
		"Title": "Default-case finding",
		"Description": "Exercises non-SecurityHub dispatch through the full pipeline.",
		"Severity": {"Label": "LOW"},
		"Resources": [{"Type": "AwsEc2Instance", "Id": "i-abc"}],
		"Compliance": {"Status": "PASSED", "StatusReasons": [{"ReasonCode": "OK", "Description": "All checks passed"}]},
		"UpdatedAt": "2026-01-01T00:00:00Z",
		"SourceUrl": "https://example.com/finding",
		"Remediation": {"Recommendation": {"Text": "Do the thing", "Url": "https://example.com/fix"}},
		"Types": ["Test"]
	}]}`)
	result, err := ConvertAsffToHDF(input, converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "scannery/rule/123", req.ID, "default case uses GeneratorId verbatim")
	require.NotNil(t, req.Title)
	assert.Equal(t, "Default-case finding", *req.Title)
	assert.InDelta(t, 0.3, req.Impact, 0.001)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	require.NotNil(t, req.Results[0].Message, "PASSED status with reason text → message populated")
	assert.Contains(t, *req.Results[0].Message, "All checks passed")

	// Default product name from companyx/scannery ARN tail.
	require.NotNil(t, result.Baselines[0].Title)
	assert.Equal(t, "companyx - scannery", *result.Baselines[0].Title)

	// Refs from SourceUrl.
	require.Len(t, req.Refs, 1)
	require.NotNil(t, req.Refs[0].URL)
	assert.Equal(t, "https://example.com/finding", *req.Refs[0].URL)

	// Fix description from Remediation.
	var hasFix bool
	for _, d := range req.Descriptions {
		if d.Label == "fix" {
			hasFix = true
			assert.Contains(t, d.Data, "Do the thing")
			assert.Contains(t, d.Data, "https://example.com/fix")
		}
	}
	assert.True(t, hasFix, "Remediation.Recommendation should land in descriptions[label=fix]")
}

func TestConvert_NoAwsAccountIdOmitsComponents(t *testing.T) {
	input := []byte(`{"Findings": [{
		"ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
		"GeneratorId": "g",
		"Title": "t",
		"Description": "d",
		"Severity": {"Label": "LOW"},
		"Resources": [],
		"Compliance": {"Status": "PASSED"},
		"UpdatedAt": "2026-01-01T00:00:00Z"
	}]}`)
	result, err := ConvertAsffToHDF(input, converterVersion)
	require.NoError(t, err)
	assert.Empty(t, result.Components, "no AwsAccountId → no Components emitted (never invent Unknown)")
}
