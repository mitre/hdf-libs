package xccdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	hdfvalidators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

func fixtureDir() string {
	return filepath.Join(shared.GetConvertersDir(), "xccdf-results-to-hdf", "fixtures", "input")
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir(), name))
	require.NoError(t, err, "Failed to read fixture %s", name)
	return data
}

// --- Error handling tests ---

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName: "xccdf-results-to-hdf",
		ConvertFn: func(input []byte) (interface{}, error) {
			return ConvertXccdfResultsToHDF(input, converterVersion)
		},
		MinimalFixture: "minimal.xml",
		InvalidInput:   "<not valid xml",
	})
}

func TestConvertXccdfResultsToHDF_NonXccdfXML(t *testing.T) {
	// Valid XML but not an XCCDF Benchmark - Go xml.Unmarshal rejects the
	// wrong root element name, so we get a parse-level error.
	input := []byte(`<?xml version="1.0"?><root><child>text</child></root>`)
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "XCCDF")
}

func TestConvertXccdfResultsToHDF_WrongNamespaceXML(t *testing.T) {
	// XCCDF-like structure but wrong namespace
	input := []byte(`<?xml version="1.0"?><Benchmark xmlns="http://wrong.namespace"><title>test</title></Benchmark>`)
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "XCCDF")
}

// --- Minimal fixture tests ---

func TestConvertXccdfResultsToHDF_Minimal(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Components, 1)

	shared.WriteOutput(t, "xccdf-results-to-hdf", "minimal.json", result)
}

func TestConvertXccdfResultsToHDF_MinimalRequirementCount(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	assert.Len(t, result.Baselines[0].Requirements, 2, "minimal.xml has 2 rule-results")
}

// --- Ground-truth anchors (input-derived counts; see shared/go/anchor.go) ---
// These assert the converter reproduces a count derived INDEPENDENTLY from the
// source, so a silent under-extraction fails even when Go and TS agree — the
// gap parity cannot see (bead nhia).

// Benchmark-only mode: the SSG fixture nests <Rule>s inside nested <Group>s, so
// the converter must flatten every group depth (the nhia regression). Assert one
// requirement per source <Rule>, counted independently of the converter's own
// traversal — this is the exact bug parity missed.
func TestConvertXccdf_BenchmarkAnchor_SSGNestedGroups(t *testing.T) {
	input := loadFixture(t, "benchmark-ssg-nested-groups.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	want := shared.CountXMLElements(t, input, "Rule")
	shared.AssertRequirementCount(t, result, want,
		"benchmark-ssg-nested-groups.xml: one requirement per <Rule> across all nested groups")
}

// Results mode: one requirement per <rule-result>, counted from the source.
func TestConvertXccdf_ResultsAnchor_StigRhel7(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	want := shared.CountXMLElements(t, input, "rule-result")
	shared.AssertRequirementCount(t, result, want,
		"stig-rhel7.xml: one requirement per <rule-result>")
}

func TestConvertXccdfResultsToHDF_MinimalStatusMapping(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// First rule-result is "fail"
	failReq := shared.MustFindRequirement(t, reqs, "xccdf_moc.elpmaxe.www_rule_1")
	assert.Equal(t, hdf.Failed, failReq.Results[0].Status)

	// Second rule-result is "pass"
	passReq := shared.MustFindRequirement(t, reqs, "xccdf_moc.elpmaxe.www_rule_2")
	assert.Equal(t, hdf.Passed, passReq.Results[0].Status)
}

func TestConvertXccdfResultsToHDF_MinimalDefaultImpact(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	// minimal.xml rules have no severity, so impact should default to 0.5
	for _, req := range result.Baselines[0].Requirements {
		assert.Equal(t, 0.5, req.Impact, "No severity should default to 0.5 for %s", req.ID)
	}
}

func TestConvertXccdfResultsToHDF_MinimalIDFallback(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	// minimal.xml rules have no <version>, so ID falls back to idref
	for _, req := range result.Baselines[0].Requirements {
		assert.Contains(t, req.ID, "xccdf_moc.elpmaxe.www_rule_",
			"ID should fall back to idref when no Rule version exists")
	}
}

func TestConvertXccdfResultsToHDF_MinimalTarget(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	assert.Equal(t, "Test Target", result.Components[0].Name)
	assert.Equal(t, hdf.Host, result.Components[0].Type)
	assert.Nil(t, result.Components[0].IPAddress, "minimal.xml has no target-address")
}

func TestConvertXccdfResultsToHDF_MinimalTimestamp(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, 2012, result.Timestamp.Year())
	assert.Equal(t, 12, int(result.Timestamp.Month()))
	assert.Equal(t, 10, result.Timestamp.Day())
}

func TestConvertXccdfResultsToHDF_MinimalDuration(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Statistics)
	require.NotNil(t, result.Statistics.Duration)
	// start-time and end-time are the same in minimal.xml
	assert.Equal(t, 0.0, *result.Statistics.Duration)
}

func TestConvertXccdfResultsToHDF_MinimalBaselineName(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	// minimal.xml has no <title>, so baseline name falls back to Benchmark id
	assert.Equal(t, "xccdf_moc.elpmaxe.www_benchmark_test", result.Baselines[0].Name)
}

func TestConvertXccdfResultsToHDF_MinimalNoNIST(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		nist, ok := req.Tags["nist"]
		assert.True(t, ok, "nist tag should be present")
		nistSlice, ok := nist.([]string)
		assert.True(t, ok, "nist should be a string slice")
		assert.Empty(t, nistSlice, "No CCI idents means empty nist")
	}
}

// --- STIG RHEL7 fixture tests ---

func TestConvertXccdfResultsToHDF_StigRhel7(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Components, 1)

	shared.WriteOutput(t, "xccdf-results-to-hdf", "stig-rhel7.json", result)
}

func TestConvertXccdfResultsToHDF_StigRequirementCount(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	assert.Len(t, result.Baselines[0].Requirements, 5, "stig-rhel7.xml has 5 rule-results")
}

func TestConvertXccdfResultsToHDF_StigBaselineName(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	assert.Equal(t, "Red Hat Enterprise Linux 7 Security Technical Implementation Guide",
		result.Baselines[0].Name)
}

func TestConvertXccdfResultsToHDF_StigControlType(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	// At least one requirement should have a derived controlType once NIST
	// tags are present via CCI mapping. The exact distribution depends on
	// the source CCIs; this just verifies the pipeline plumbing works.
	var sawDerivation bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawDerivation = true
			// Sanity check: must be one of the known classification values.
			switch *req.ControlType {
			case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
			default:
				t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
			}
		}
	}
	assert.True(t, sawDerivation, "at least one stig-rhel7 requirement should have a derived controlType")
}

func TestConvertXccdfResultsToHDF_StigSeverityToImpact(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// SV-204393: medium -> 0.5
	medReq := shared.MustFindRequirement(t, reqs, "SV-204393")
	assert.Equal(t, 0.5, medReq.Impact, "medium severity should map to 0.5")

	// SV-204424: high -> 0.7
	highReq := shared.MustFindRequirement(t, reqs, "SV-204424")
	assert.Equal(t, 0.7, highReq.Impact, "high severity should map to 0.7")

	// SV-204452: low -> 0.3
	lowReq := shared.MustFindRequirement(t, reqs, "SV-204452")
	assert.Equal(t, 0.3, lowReq.Impact, "low severity should map to 0.3")
}

// The results path derives impact from severity but historically never set the
// requirement.severity enum, unlike the baseline path. Pin the parity: a
// results-path requirement must carry the same HDF severity the baseline path
// would emit for the rule.
func TestConvertXccdfResultsToHDF_StigSeverityEnum(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	medReq := shared.MustFindRequirement(t, reqs, "SV-204393")
	require.NotNil(t, medReq.Severity, "medium rule must carry a severity")
	assert.Equal(t, hdf.SeverityMedium, *medReq.Severity)

	highReq := shared.MustFindRequirement(t, reqs, "SV-204424")
	require.NotNil(t, highReq.Severity, "high rule must carry a severity")
	assert.Equal(t, hdf.SeverityHigh, *highReq.Severity)

	lowReq := shared.MustFindRequirement(t, reqs, "SV-204452")
	require.NotNil(t, lowReq.Severity, "low rule must carry a severity")
	assert.Equal(t, hdf.SeverityLow, *lowReq.Severity)
}

// SCC output carries @severity on each rule-result but ships no Rule
// definitions, so severity must come from the rule-result attribute alone.
func TestConvertXccdfResultsToHDF_SccSeverityFromRuleResult(t *testing.T) {
	input := loadFixture(t, "xccdf-results-scc-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "SV-204393")
	require.NotNil(t, req.Severity, "rule-result severity must populate requirement.severity")
	assert.Equal(t, hdf.SeverityMedium, *req.Severity)
}

// XCCDF severity="unknown" has no HDF equivalent; the results path must omit
// severity rather than fabricate one. arf-minimal's sole rule-result is unknown.
func TestConvertXccdfResultsToHDF_UnknownSeverityOmitted(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Nil(t, req.Severity, `severity="unknown" must not be emitted`)
}

// When the rule-result omits @severity, the severity falls back to the Rule
// definition — mirroring the impact precedence. Also pins that a rule-result
// with no matching rule and no severity emits no severity at all.
func TestConvertXccdfResultsToHDF_SeverityPrecedenceAndAbsent(t *testing.T) {
	input := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_benchmark_sev">
  <version>1.0</version>
  <Rule id="xccdf_test_rule_1" selected="true" severity="high">
    <title>Rule with severity</title>
    <description>desc</description>
  </Rule>
  <TestResult id="xccdf_test_testresult_1" start-time="2021-01-01T00:00:00">
    <target>host</target>
    <rule-result idref="xccdf_test_rule_1" time="2021-01-01T00:00:00">
      <result>fail</result>
    </rule-result>
    <rule-result idref="xccdf_unmatched_rule" time="2021-01-01T00:00:00">
      <result>pass</result>
    </rule-result>
  </TestResult>
</Benchmark>`)
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.Len(t, reqs, 2)

	// rule-result had no @severity → falls back to the Rule's high.
	require.NotNil(t, reqs[0].Severity)
	assert.Equal(t, hdf.SeverityHigh, *reqs[0].Severity)

	// No matching rule and no rule-result @severity → omitted.
	assert.Nil(t, reqs[1].Severity)
}

func TestConvertXccdfResultsToHDF_StigStatusMapping(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// SV-204393: fail
	failReq := shared.MustFindRequirement(t, reqs, "SV-204393")
	assert.Equal(t, hdf.Failed, failReq.Results[0].Status)

	// SV-204405: pass
	passReq := shared.MustFindRequirement(t, reqs, "SV-204405")
	assert.Equal(t, hdf.Passed, passReq.Results[0].Status)
}

func TestConvertXccdfResultsToHDF_StigCCIToNIST(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "SV-204393")

	// Should have cci tag
	cciTag, ok := req.Tags["cci"]
	require.True(t, ok, "Should have cci tag")
	cciSlice, ok := cciTag.([]string)
	require.True(t, ok, "cci should be a string slice")
	assert.Contains(t, cciSlice, "CCI-000048")

	// Should have nist tag derived from CCI
	nistTag, ok := req.Tags["nist"]
	require.True(t, ok, "Should have nist tag")
	nistSlice, ok := nistTag.([]string)
	require.True(t, ok, "nist should be a string slice")
	assert.NotEmpty(t, nistSlice, "NIST mapping should not be empty for CCI-000048")
}

// --- Rule/group identifier tags (stig_id, cce, legacy_id, gid, gtitle) ---

func TestConvertXccdfResultsToHDF_StigRuleGroupTags(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "SV-204393")

	assert.Equal(t, "RHEL-07-010030", req.Tags["stig_id"], "stig_id from rule-result @version")
	assert.Equal(t, "CCE-26970-4", req.Tags["cce"], "cce from CCE ident")
	assert.Equal(t, []string{"V-71859", "SV-86483"}, req.Tags["legacy_id"], "legacy_id array in source order")
	assert.Equal(t, "xccdf_mil.disa.stig_group_V-204393", req.Tags["gid"], "gid from enclosing Group @id")
	assert.Equal(t, "SRG-OS-000023-GPOS-00006", req.Tags["gtitle"], "gtitle from Group title")
}

// rhel8 carries stig_id + gid/gtitle but no CCE or legacy idents — the
// present/absent split proves each key is source-gated independently.
func TestConvertXccdfResultsToHDF_Rhel8NoCCEorLegacy(t *testing.T) {
	input := loadFixture(t, "xccdf-results-openscap-rhel8.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "SV-230221")

	assert.Equal(t, "RHEL-08-010000", req.Tags["stig_id"])
	assert.Equal(t, "xccdf_mil.disa.stig_group_V-230221", req.Tags["gid"])
	assert.Equal(t, "SRG-OS-000480-GPOS-00227", req.Tags["gtitle"])

	_, hasCCE := req.Tags["cce"]
	assert.False(t, hasCCE, "no CCE ident in rhel8 → cce omitted")
	_, hasLegacy := req.Tags["legacy_id"]
	assert.False(t, hasLegacy, "no legacy ident in rhel8 → legacy_id omitted")
}

// minimal.xml has top-level rules with no version, no idents, no Group — every
// added key must be absent (the fully-empty branch).
func TestConvertXccdfResultsToHDF_MinimalNoRuleGroupTags(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, key := range []string{"stig_id", "cce", "legacy_id", "gid", "gtitle"} {
			_, ok := req.Tags[key]
			assert.Falsef(t, ok, "%s should be absent for un-grouped, version-less rule", key)
		}
	}
}

func TestConvertXccdfResultsToHDF_StigTarget(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	target := result.Components[0]
	assert.Equal(t, "localhost.localdomain", target.Name)
	assert.Equal(t, hdf.Host, target.Type)
	require.NotNil(t, target.IPAddress)
	assert.Equal(t, "127.0.0.1", *target.IPAddress)
}

func TestConvertXccdfResultsToHDF_StigDuration(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Statistics)
	require.NotNil(t, result.Statistics.Duration)
	// start-time 2021-12-17T10:39:29, end-time 2021-12-17T10:40:58 = 89 seconds
	assert.Equal(t, 89.0, *result.Statistics.Duration)
}

func TestConvertXccdfResultsToHDF_StigTimestamp(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, 2021, result.Timestamp.Year())
	assert.Equal(t, 12, int(result.Timestamp.Month()))
	assert.Equal(t, 17, result.Timestamp.Day())
}

func TestConvertXccdfResultsToHDF_StigDescriptions(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "SV-204393")

	// Should have at least "default" and "fix" descriptions
	require.GreaterOrEqual(t, len(req.Descriptions), 2)

	defaultDesc := findDescription(req.Descriptions, "default")
	require.NotNil(t, defaultDesc, "Should have default description")
	assert.NotEmpty(t, defaultDesc.Data, "Default description should not be empty")
	assert.Contains(t, defaultDesc.Data, "standardized and approved use notification")

	fixDesc := findDescription(req.Descriptions, "fix")
	require.NotNil(t, fixDesc, "Should have fix description")
	assert.NotEmpty(t, fixDesc.Data, "Fix description should not be empty")
}

// The results path historically emitted only default+fix descriptions, dropping
// the check (OVAL/SCE) description that the baseline path already produces. Pin
// the restored parity: a rule-result whose rule carries inline check-content
// must surface it as a "check" description, exactly like the baseline path.
func TestConvertXccdfResultsToHDF_ResultsPathCheckDescription(t *testing.T) {
	input := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_benchmark_1">
  <version>1.0</version>
  <Rule id="xccdf_test_rule_1" selected="true" severity="medium">
    <title>Test rule</title>
    <description>&lt;VulnDiscussion&gt;Some discussion&lt;/VulnDiscussion&gt;</description>
    <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
      <check-content>OVAL definition logic goes here</check-content>
      <check-content-ref name="oval:x:def:1" href="oval.xml"/>
    </check>
  </Rule>
  <TestResult id="xccdf_test_testresult_1" start-time="2021-01-01T00:00:00">
    <target>host</target>
    <rule-result idref="xccdf_test_rule_1" time="2021-01-01T00:00:00">
      <result>fail</result>
    </rule-result>
  </TestResult>
</Benchmark>`)
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	checkDesc := findDescription(req.Descriptions, "check")
	require.NotNil(t, checkDesc, "results path must emit a check description (parity with baseline path)")
	assert.Contains(t, checkDesc.Data, "OVAL definition logic goes here")
}

// requirement.code must carry the automated-check logic (OVAL/SCE
// check-content-ref name/href + any inline check-content), the natural CODE-tab
// fill. Pinned against the real stig-rhel7 OVAL reference.
func TestConvertXccdfResultsToHDF_RequirementCode(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "SV-204393")
	require.NotNil(t, req.Code, "requirement.code must be set from the OVAL check")

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(*req.Code), &parsed), "code must be valid JSON")
	assert.Equal(t, "http://oval.mitre.org/XMLSchema/oval-definitions-5", parsed["system"])
	ref, ok := parsed["checkContentRef"].(map[string]interface{})
	require.True(t, ok, "code must carry checkContentRef")
	assert.Equal(t, "oval:mil.disa.stig.rhel7:def:922", ref["name"])
	assert.Contains(t, ref["href"], "oval.xml")
}

// A rule with no check element must leave code unset (NOT-IN-SOURCE) rather than
// fabricate a value.
func TestConvertXccdfResultsToHDF_RequirementCodeUnsetWhenNoCheck(t *testing.T) {
	input := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_benchmark_2">
  <version>1.0</version>
  <Rule id="xccdf_test_rule_1" selected="true" severity="low">
    <title>No check rule</title>
    <description>desc</description>
  </Rule>
  <TestResult id="xccdf_test_testresult_1" start-time="2021-01-01T00:00:00">
    <target>host</target>
    <rule-result idref="xccdf_test_rule_1" time="2021-01-01T00:00:00">
      <result>pass</result>
    </rule-result>
  </TestResult>
</Benchmark>`)
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Nil(t, req.Code, "code must be unset when the rule has no check element")
}

// buildCheckCode branch coverage: exercises every path the fixtures don't reach
// (all fixtures carry a check-content-ref with empty inline check-content).
func TestBuildCheckCode(t *testing.T) {
	// Empty check → unset (the "no check element" guard).
	assert.Equal(t, "", buildCheckCode(Check{}), "empty check must yield no code")

	// Whitespace-only check-content with no system/ref is still empty → unset.
	assert.Equal(t, "", buildCheckCode(Check{CheckContent: "   \n  "}), "blank check-content must yield no code")

	// Inline check-content present, no content-ref: checkContent is trimmed and
	// included; checkContentRef is omitted.
	contentOnly := buildCheckCode(Check{
		System:       "http://oval.mitre.org/XMLSchema/oval-definitions-5",
		CheckContent: "  OVAL definition logic  ",
	})
	assert.Contains(t, contentOnly, `"checkContent": "OVAL definition logic"`)
	assert.NotContains(t, contentOnly, "checkContentRef")

	// Content-ref present with no system: system key omitted, ref present.
	refNoSystem := buildCheckCode(Check{
		CheckContentRef: CheckContentRef{Name: "oval:x:def:1", Href: "oval.xml"},
	})
	assert.NotContains(t, refNoSystem, `"system"`)
	assert.Contains(t, refNoSystem, `"name": "oval:x:def:1"`)
	assert.Contains(t, refNoSystem, `"href": "oval.xml"`)

	// All fields present: system + ref + inline content.
	full := buildCheckCode(Check{
		System:          "sce",
		CheckContent:    "logic",
		CheckContentRef: CheckContentRef{Name: "n", Href: "h"},
	})
	assert.Contains(t, full, `"system": "sce"`)
	assert.Contains(t, full, `"checkContentRef"`)
	assert.Contains(t, full, `"checkContent": "logic"`)
}

// Impact is the severity the benchmark assigned, whatever the rule-result's
// disposition: a deselected or informational high-severity rule is still a
// high-severity rule that was not evaluated, and zeroing it would restate the
// disposition in a field nothing reads for status. The disposition travels in
// the result status instead.
func TestConvertXccdfResultsToHDF_ImpactIsSeverityNotDisposition(t *testing.T) {
	input := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_benchmark_impact">
  <version>1.0</version>
  <Rule id="rule_na" selected="true" severity="high"><title>NA</title></Rule>
  <Rule id="rule_ns" selected="true" severity="high"><title>NS</title></Rule>
  <Rule id="rule_info" selected="true" severity="high"><title>INFO</title></Rule>
  <Rule id="rule_fail" selected="true" severity="high"><title>FAIL</title></Rule>
  <TestResult id="xccdf_test_tr" start-time="2021-01-01T00:00:00">
    <target>host</target>
    <rule-result idref="rule_na" time="2021-01-01T00:00:00"><result>notapplicable</result></rule-result>
    <rule-result idref="rule_ns" time="2021-01-01T00:00:00"><result>notselected</result></rule-result>
    <rule-result idref="rule_info" time="2021-01-01T00:00:00"><result>informational</result></rule-result>
    <rule-result idref="rule_fail" time="2021-01-01T00:00:00"><result>fail</result></rule-result>
  </TestResult>
</Benchmark>`)
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	byTitle := func(title string) hdf.EvaluatedRequirement {
		for _, r := range reqs {
			if r.Title != nil && *r.Title == title {
				return r
			}
		}
		t.Fatalf("requirement %q not found", title)
		return hdf.EvaluatedRequirement{}
	}
	assert.Equal(t, 0.7, byTitle("NA").Impact, "notapplicable keeps the rule's high severity")
	assert.Equal(t, 0.7, byTitle("NS").Impact, "notselected keeps the rule's high severity")
	assert.Equal(t, 0.7, byTitle("INFO").Impact, "informational keeps the rule's high severity")
	assert.Equal(t, 0.7, byTitle("FAIL").Impact, "a real failed high-severity rule keeps its impact")

	// The dispositions are carried here instead.
	assert.Equal(t, hdf.NotApplicable, byTitle("NA").Results[0].Status)
	assert.Equal(t, hdf.NotApplicable, byTitle("NS").Results[0].Status)
	assert.Equal(t, hdf.NotApplicable, byTitle("INFO").Results[0].Status)
	assert.Equal(t, hdf.Failed, byTitle("FAIL").Results[0].Status)
}

// The <reference> element on a STIG rule (Dublin Core publisher/identifier/type)
// must surface into requirement.refs — heimdall2 emits it and ours formerly
// dropped it entirely. Pinned against the real stig-rhel7 DPMS reference.
func TestConvertXccdfResultsToHDF_Refs(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "SV-204393")
	require.Len(t, req.Refs, 1, "the DPMS reference must produce one ref")
	require.NotNil(t, req.Refs[0].Ref, "ref must carry the Dublin Core object")
	require.Len(t, req.Refs[0].Ref.AnythingMapArray, 1)
	obj := req.Refs[0].Ref.AnythingMapArray[0]
	assert.Equal(t, "DISA", obj["publisher"])
	assert.Equal(t, "2899", obj["identifier"])
	assert.Equal(t, "DPMS Target", obj["type"])
	assert.Nil(t, req.Refs[0].URL, "rule-level DPMS references carry no href")
}

// heimdall2 sources the "check" description from the OVAL/SCE definition name
// (check-content-ref/@name), which SCAP content populates instead of inline
// check logic. Ours previously read only the (empty) inline content and emitted
// no check description. Pin the OVAL-name fallback against stig-rhel7.
func TestConvertXccdfResultsToHDF_CheckDescriptionFromOvalName(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "SV-204393")
	checkDesc := findDescription(req.Descriptions, "check")
	require.NotNil(t, checkDesc, "check description must be sourced from the OVAL definition name")
	assert.Equal(t, "oval:mil.disa.stig.rhel7:def:922", checkDesc.Data)
}

// The baseline path must emit rationale and warning descriptions when the source
// Rule carries them, and text-body references (SSG/CIS style) with their href as
// url. Pinned against benchmark-ssg-nested-groups.
func TestConvertXccdfBenchmarkToHDF_RationaleWarningAndTextRefs(t *testing.T) {
	input := loadFixture(t, "benchmark-ssg-nested-groups.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	findReq := func(id string) *hdf.BaselineRequirement {
		for i := range result.Requirements {
			if result.Requirements[i].ID == id {
				return &result.Requirements[i]
			}
		}
		t.Fatalf("requirement %q not found", id)
		return nil
	}

	// dnsmasq rule carries a <rationale>.
	dnsmasq := findReq("xccdf_org.ssgproject.content_rule_package_dnsmasq_removed")
	rationale := findDescription(dnsmasq.Descriptions, "rationale")
	require.NotNil(t, rationale, "rationale description must be emitted")
	assert.Contains(t, rationale.Data, "specifically designated to act as a DNS")

	// dnssec keygen rule carries a <warning>, and a text-body <reference> + href.
	named := findReq("xccdf_org.ssgproject.content_rule_service_dnsmasq_disabled")
	require.Len(t, named.Refs, 1)
	require.NotNil(t, named.Refs[0].Ref)
	require.NotNil(t, named.Refs[0].Ref.String, "text-body reference must serialize as a string")
	assert.Equal(t, "2.1.6", *named.Refs[0].Ref.String)
	require.NotNil(t, named.Refs[0].URL)
	assert.Equal(t, "https://www.cisecurity.org/benchmark/red_hat_linux/", *named.Refs[0].URL)
}

// A rule carrying a <warning> must surface it as a warning description.
func TestConvertXccdfBenchmarkToHDF_WarningDescription(t *testing.T) {
	input := loadFixture(t, "benchmark-ssg-nested-groups.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	var found bool
	for i := range result.Requirements {
		if w := findDescription(result.Requirements[i].Descriptions, "warning"); w != nil {
			assert.NotEmpty(t, w.Data)
			found = true
		}
	}
	assert.True(t, found, "at least one rule carries a <warning> that must become a description")
}

func TestConvertXccdfResultsToHDF_StigRuleVersionAsID(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// All STIG rules should use version text as ID
	expectedIDs := []string{
		"SV-204393",
		"SV-204396",
		"SV-204405",
		"SV-204424",
		"SV-204452",
	}
	for _, expectedID := range expectedIDs {
		shared.MustFindRequirement(t, reqs, expectedID)
	}
}

// --- Generator and Tool tests ---

func TestConvertXccdfResultsToHDF_Generator(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "xccdf-results-to-hdf", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
}

func TestConvertXccdfResultsToHDF_Tool(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "XCCDF", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "XCCDF", *result.Tool.Format)
}

// TestConvertXccdfResultsToHDF_ToolVersion pins the scanner version lifted from
// the TestResult @test-system CPE ("cpe:/a:redhat:openscap:1.2.17"), proving the
// value is source-derived rather than dropped.
func TestConvertXccdfResultsToHDF_ToolVersion(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Version)
	assert.Equal(t, "1.2.17", *result.Tool.Version)
	// Name/format stay the format identity; version enriches it.
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "XCCDF", *result.Tool.Name)
}

// TestConvertXccdfResultsToHDF_ToolVersion_SCC pins the SCC scanner version from
// "cpe:/a:spawar:scc:5.4.2".
func TestConvertXccdfResultsToHDF_ToolVersion_SCC(t *testing.T) {
	input := loadFixture(t, "xccdf-results-scc-rhel8.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Version)
	assert.Equal(t, "5.4.2", *result.Tool.Version)
}

// TestConvertXccdfResultsToHDF_ToolVersion_Absent covers the fallback branch: a
// TestResult with no @test-system leaves tool.version unset (never fabricated).
func TestConvertXccdfResultsToHDF_ToolVersion_Absent(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	assert.Nil(t, result.Tool.Version)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "XCCDF", *result.Tool.Name)
}

// TestConvertARF_ToolVersion pins the scanner version from the ARF report's
// embedded TestResult @test-system ("cpe:/a:redhat:openscap:1.3.5").
func TestConvertARF_ToolVersion(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Version)
	assert.Equal(t, "1.3.5", *result.Tool.Version)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "ARF", *result.Tool.Name)
}

// TestParseCPEVersion covers every branch of the CPE version parser directly,
// including malformed inputs that no fixture exercises.
func TestParseCPEVersion(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"openscap", "cpe:/a:redhat:openscap:1.3.5", "1.3.5"},
		{"scc", "cpe:/a:spawar:scc:5.4.2", "5.4.2"},
		{"empty", "", ""},
		{"non-cpe", "OpenSCAP 1.3.6", ""},
		{"cpe without version", "cpe:/a:redhat:openscap", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseCPEVersion(tc.input))
		})
	}
}

func TestConvertXccdfResultsToHDF_ResultsChecksum(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	checksum := result.Baselines[0].ResultsChecksum
	require.NotNil(t, checksum)
	assert.Equal(t, hdf.Sha256, checksum.Algorithm)
	assert.Len(t, checksum.Value, 64, "SHA-256 hex string should be 64 chars")
}

// --- Unit tests for internal helpers ---

func TestMapResultStatus(t *testing.T) {
	tests := []struct {
		input    string
		expected hdf.ResultStatus
	}{
		{"pass", hdf.Passed},
		{"fail", hdf.Failed},
		{"error", hdf.Error},
		{"unknown", hdf.Error},
		{"notapplicable", hdf.NotApplicable},
		{"notchecked", hdf.NotReviewed},
		{"notselected", hdf.NotApplicable},
		{"informational", hdf.NotApplicable},
		{"fixed", hdf.Passed},
		{"PASS", hdf.Passed},
		{"Fail", hdf.Failed},
		{"bogus", hdf.Error},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, mapResultStatus(tt.input))
		})
	}
}

func TestBuildBaselineTags_DescriptionSubElements(t *testing.T) {
	rule := &Rule{Description: Prose("<VulnDiscussion>Why</VulnDiscussion>" +
		"<FalsePositives></FalsePositives><FalseNegatives></FalseNegatives>" +
		"<Documentable>true</Documentable>" +
		"<Mitigations>Use <b>TLS</b></Mitigations>" +
		"<SeverityOverrideGuidance>Elevate to CAT I if world-writable.</SeverityOverrideGuidance>" +
		"<Responsibility>System Administrator</Responsibility>" +
		"<Responsibility>Information Assurance Officer</Responsibility>" +
		"<IAControls>ECAR-1, ECAR-2</IAControls>")}
	tags := buildBaselineTags(rule, nil)

	assert.Equal(t, true, tags["documentable"])
	assert.Equal(t, []string{"System Administrator", "Information Assurance Officer"}, tags["responsibility"])
	assert.Equal(t, "ECAR-1, ECAR-2", tags["ia_controls"])
	assert.Equal(t, "Use TLS", tags["mitigations"])
	assert.Equal(t, "Elevate to CAT I if world-writable.", tags["severity_override_guidance"])
	for _, absent := range []string{"false_positives", "false_negatives", "potential_impacts", "third_party_tools", "mitigation_control", "vuln_discussion"} {
		_, has := tags[absent]
		assert.False(t, has, "empty or non-tag sub-element must not produce %q", absent)
	}
}

func TestBuildBaselineTags_DocumentableNotBooleanIsOmitted(t *testing.T) {
	rule := &Rule{Description: Prose("<VulnDiscussion>Why</VulnDiscussion><Documentable>maybe</Documentable>")}
	tags := buildBaselineTags(rule, nil)
	_, has := tags["documentable"]
	assert.False(t, has)
}

func TestBuildBaselineTags_SecurityOverrideGuidanceSpelling(t *testing.T) {
	// DISA spelled the element SecurityOverrideGuidance until 2012; it holds the
	// same guidance and lands in the same tag.
	old := &Rule{Description: Prose("<VulnDiscussion>Why</VulnDiscussion>" +
		"<SecurityOverrideGuidance>Elevate to CAT I if unpatched.</SecurityOverrideGuidance>")}
	assert.Equal(t, "Elevate to CAT I if unpatched.", buildBaselineTags(old, nil)["severity_override_guidance"])

	both := &Rule{Description: Prose("<VulnDiscussion>Why</VulnDiscussion>" +
		"<SecurityOverrideGuidance>Old text</SecurityOverrideGuidance>" +
		"<SeverityOverrideGuidance>Current text</SeverityOverrideGuidance>")}
	assert.Equal(t, "Current text", buildBaselineTags(both, nil)["severity_override_guidance"])

	empty := &Rule{Description: Prose("<VulnDiscussion>Why</VulnDiscussion>" +
		"<SecurityOverrideGuidance></SecurityOverrideGuidance>")}
	_, has := buildBaselineTags(empty, nil)["severity_override_guidance"]
	assert.False(t, has)
}

func TestBenchmark_DISADescriptionSubElementTags(t *testing.T) {
	sles := loadFixture(t, "U_SLES_V11_for_System_z_STIG_V1R12_Manual-xccdf.xml")
	result, err := ConvertXccdfBenchmarkToHDF(sles, converterVersion)
	require.NoError(t, err)
	byID := make(map[string]hdf.BaselineRequirement, len(result.Requirements))
	for _, r := range result.Requirements {
		byID[r.ID] = r
	}
	require.Contains(t, byID, "SV-44791")
	assert.Equal(t, true, byID["SV-44791"].Tags["documentable"])
	assert.Equal(t, false, byID["SV-44760"].Tags["documentable"])
	assert.Equal(t, []string{"System Administrator", "Information Assurance Officer"}, byID["SV-45877"].Tags["responsibility"])
	assert.Equal(t, []string{"System Administrator"}, byID["SV-44760"].Tags["responsibility"])
	fp, _ := byID["SV-45872"].Tags["false_positives"].(string)
	assert.True(t, strings.HasPrefix(fp, "False positives may occur with the SMTP EXPN check"), "got %q", fp)
	assert.Equal(t, "GEN000000-FW", byID["SV-45723"].Tags["mitigations"])
	mc, _ := byID["SV-45723"].Tags["mitigation_control"].(string)
	assert.True(t, strings.HasPrefix(mc, "The system's firewall default-deny policy"), "got %q", mc)
	assert.Equal(t, "ECAR-1, ECAR-2, ECAR-3", byID["SV-45286"].Tags["ia_controls"])

	mfd := loadFixture(t, "U_Multifunction_Device_and_Network_Printers_STIG_V2R15_Manual-xccdf.xml")
	result, err = ConvertXccdfBenchmarkToHDF(mfd, converterVersion)
	require.NoError(t, err)
	var pi string
	for _, r := range result.Requirements {
		if r.ID == "SV-7015" {
			pi, _ = r.Tags["potential_impacts"].(string)
		}
	}
	assert.True(t, strings.HasPrefix(pi, "Print clients configured to use the unauthorized port(s)"), "got %q", pi)

	mac := loadFixture(t, "U_Mac_10.5_V1R2_STIG_Manual-XCCDF.xml")
	result, err = ConvertXccdfBenchmarkToHDF(mac, converterVersion)
	require.NoError(t, err)
	var sog string
	for _, r := range result.Requirements {
		if r.ID == "SV-31297" {
			sog, _ = r.Tags["severity_override_guidance"].(string)
		}
	}
	assert.True(t, strings.HasPrefix(sog, "If any of the patches not installed are"), "got %q", sog)

	ie8 := loadFixture(t, "U_Microsoft_IE8_V1R19_Manual-xccdf.xml")
	result, err = ConvertXccdfBenchmarkToHDF(ie8, converterVersion)
	require.NoError(t, err)
	var tpt string
	for _, r := range result.Requirements {
		if r.ID == "SV-25182" {
			tpt, _ = r.Tags["third_party_tools"].(string)
		}
	}
	assert.Equal(t, "HK", tpt)
}

func TestExtractVulnDiscussion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "with VulnDiscussion tags",
			input:    "<VulnDiscussion>Important security info</VulnDiscussion><other>ignored</other>",
			expected: "Important security info",
		},
		{
			name:     "no VulnDiscussion tags",
			input:    "Plain text description",
			expected: "Plain text description",
		},
		{
			name:     "empty VulnDiscussion",
			input:    "<VulnDiscussion></VulnDiscussion>",
			expected: "",
		},
		{
			name:     "VulnDiscussion with nested HTML",
			input:    "<VulnDiscussion>Info with <b>bold</b> text</VulnDiscussion>",
			expected: "Info with <b>bold</b> text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractVulnDiscussion(tt.input))
		})
	}
}

func TestSeverityToImpactMapping(t *testing.T) {
	// XCCDF uses standard severity levels via hdfutil.SeverityToImpact with default 0.5.
	tests := []struct {
		severity string
		expected float64
	}{
		{"high", 0.7},
		{"medium", 0.5},
		{"low", 0.3},
		{"critical", 0.9}, // Standard mapping (XCCDF doesn't use critical, but it's valid)
		{"", 0.5},         // Unknown/empty falls back to default
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			assert.Equal(t, tt.expected, hdfutil.SeverityToImpact(tt.severity, 0.5))
		})
	}
}

func TestDedup(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{"no duplicates", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"with duplicates", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"empty", []string{}, nil},
		{"single", []string{"a"}, []string{"a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dedup(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKebabCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"MS_Windows_Server_2022_STIG", "ms-windows-server-2022-stig"},
		{"simple", "simple"},
		{"UPPER_CASE", "upper-case"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, kebabCase(tt.input))
		})
	}
}

// --- ARF fixture tests ---

func TestConvertARF_Minimal(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Components, 1)

	// Should produce 1 requirement from 1 rule-result
	assert.Len(t, result.Baselines[0].Requirements, 1)

	// The rule-result is a "fail"
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, hdf.Failed, req.Results[0].Status)

	shared.WriteOutput(t, "xccdf-results-to-hdf", "arf-minimal.json", result)
}

func TestConvertARF_AssetMetadata(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	target := result.Components[0]

	// Target name from TestResult <target> element
	assert.Equal(t, "rh-hony", target.Name)
	assert.Equal(t, hdf.Host, target.Type)

	// IP address from TestResult target-address (first IPv4)
	require.NotNil(t, target.IPAddress)
	assert.Equal(t, "127.0.0.1", *target.IPAddress)

	// ARF asset enrichment: FQDN and hostname from computing-device
	require.NotNil(t, target.FQDN)
	assert.Equal(t, "rh-hony", *target.FQDN)

	// MAC address from ARF asset connections
	require.NotNil(t, target.MACAddress)
	assert.NotEmpty(t, *target.MACAddress)
}

func TestConvertARF_SkipsOVALReports(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	// arf-minimal.xml has 2 reports: one XCCDF TestResult and one OVAL.
	// Only the XCCDF report should produce a baseline.
	assert.Len(t, result.Baselines, 1)
}

func TestConvertARF_BaselineName(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	// Baseline name from embedded Benchmark title
	assert.Equal(t, "Test Benchmark", result.Baselines[0].Name)
}

func TestConvertARF_Tool(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "ARF", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "ARF", *result.Tool.Format)
}

func TestConvertARF_ResultsChecksum(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	checksum := result.Baselines[0].ResultsChecksum
	require.NotNil(t, checksum)
	assert.Equal(t, hdf.Sha256, checksum.Algorithm)
	assert.Len(t, checksum.Value, 64, "SHA-256 hex string should be 64 chars")
}

func TestConvertARF_Timestamp(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, 2021, result.Timestamp.Year())
	assert.Equal(t, 11, int(result.Timestamp.Month()))
	assert.Equal(t, 30, result.Timestamp.Day())
}

func TestConvertARF_Generator(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "xccdf-results-to-hdf", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
}

func TestConvertARF_ExistingXccdfStillWorks(t *testing.T) {
	// Regression: raw XCCDF input must still work after adding ARF detection
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Baselines[0].Requirements, 5)
}

func TestConvertXccdfResultsToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertXccdfResultsToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

// --- XCCDF 1.1 namespace tests ---

func TestConvertXccdfResultsToHDF_XCCDF11Rejected(t *testing.T) {
	// XCCDF 1.1 benchmark without TestResult should error when calling
	// ConvertXccdfResultsToHDF (requires TestResult)
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no TestResult")
}

func TestConvertXccdfResultsToHDF_XCCDF12Rejected(t *testing.T) {
	// XCCDF 1.2 benchmark without TestResult should error when calling
	// ConvertXccdfResultsToHDF (requires TestResult)
	input := loadFixture(t, "benchmark-minimal-1.2.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no TestResult")
}

// --- Benchmark-to-Baseline tests ---

func TestConvertXccdfBenchmarkToHDF_Minimal11(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "ms-windows-server-2022-stig", result.Name)
	require.NotNil(t, result.Title)
	assert.Equal(t, "Microsoft Windows Server 2022 Security Technical Implementation Guide", *result.Title)
	require.NotNil(t, result.Version)
	assert.Equal(t, "2", *result.Version)
	require.NotNil(t, result.Summary)
	assert.Contains(t, *result.Summary, "Security Technical Implementation Guide")

	assert.Len(t, result.Requirements, 3)
	assert.Len(t, result.Groups, 3)
}

func TestConvertXccdfBenchmarkToHDF_Minimal12(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.2.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should produce identical structure regardless of namespace
	assert.Equal(t, "ms-windows-server-2022-stig", result.Name)
	assert.Len(t, result.Requirements, 3)
}

func TestConvertXccdfBenchmarkToHDF_RequirementIDs(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	ids := make([]string, len(result.Requirements))
	for i, req := range result.Requirements {
		ids[i] = req.ID
	}

	// IDs should use Rule <version> text (STIG IDs)
	assert.Contains(t, ids, "SV-254238")
	assert.Contains(t, ids, "SV-254239")
	assert.Contains(t, ids, "SV-254240")
}

func TestConvertXccdfBenchmarkToHDF_SeverityMapping(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	reqMap := make(map[string]hdf.BaselineRequirement)
	for _, req := range result.Requirements {
		reqMap[req.ID] = req
	}

	// WN22-00-000010: medium -> 0.5
	assert.Equal(t, 0.5, reqMap["SV-254238"].Impact)
	// WN22-00-000030: high -> 0.7
	assert.Equal(t, 0.7, reqMap["SV-254240"].Impact)
}

func TestConvertXccdfBenchmarkToHDF_Descriptions(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	req := findBaselineRequirement(result.Requirements, "SV-254238")
	require.NotNil(t, req)

	// Should have default, check, and fix descriptions
	defaultDesc := findDescription(req.Descriptions, "default")
	require.NotNil(t, defaultDesc)
	assert.Contains(t, defaultDesc.Data, "privileged account")
	assert.NotContains(t, defaultDesc.Data, "<VulnDiscussion>")

	checkDesc := findDescription(req.Descriptions, "check")
	require.NotNil(t, checkDesc)
	assert.Contains(t, checkDesc.Data, "administrative privileges")

	fixDesc := findDescription(req.Descriptions, "fix")
	require.NotNil(t, fixDesc)
	assert.Contains(t, fixDesc.Data, "separate account")
}

func TestConvertXccdfBenchmarkToHDF_CCITags(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	req := findBaselineRequirement(result.Requirements, "SV-254238")
	require.NotNil(t, req)

	cciTag, ok := req.Tags["cci"]
	require.True(t, ok)
	cciSlice, ok := cciTag.([]string)
	require.True(t, ok)
	assert.Contains(t, cciSlice, "CCI-000366")

	nistTag, ok := req.Tags["nist"]
	require.True(t, ok)
	nistSlice, ok := nistTag.([]string)
	require.True(t, ok)
	assert.NotEmpty(t, nistSlice)
}

func TestConvertXccdfBenchmarkToHDF_MultipleCCIs(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	req := findBaselineRequirement(result.Requirements, "SV-254239")
	require.NotNil(t, req)

	cciTag, ok := req.Tags["cci"]
	require.True(t, ok)
	cciSlice, ok := cciTag.([]string)
	require.True(t, ok)
	// WN22-00-000020 has 2 CCI idents
	assert.Len(t, cciSlice, 2)
	assert.Contains(t, cciSlice, "CCI-004066")
	assert.Contains(t, cciSlice, "CCI-000199")
}

func TestConvertXccdfBenchmarkToHDF_STIGTags(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	req := findBaselineRequirement(result.Requirements, "SV-254238")
	require.NotNil(t, req)

	assert.Equal(t, "SV-254238r991589_rule", req.Tags["rid"])
	assert.Equal(t, "WN22-00-000010", req.Tags["stig_id"])
	assert.Equal(t, "medium", req.Tags["severity"])
	assert.Equal(t, "C-57723r848528_chk", req.Tags["check_id"])
	assert.Equal(t, "F-57674r848529_fix", req.Tags["fix_id"])
	assert.Equal(t, "V-254238", req.Tags["gid"])
	assert.Equal(t, "SRG-OS-000480-GPOS-00227", req.Tags["gtitle"])
}

func TestConvertXccdfBenchmark_MultiCheckPrefersOval(t *testing.T) {
	input := loadFixture(t, "benchmark-ssg-nested-groups.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	const ovalSystem = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
	// These SSG rules carry several <check> elements (OVAL + OCIL/SCE). check_id
	// must deterministically prefer the automated OVAL check, not whichever check
	// the content author happened to place last in document order.
	for _, rid := range []string{
		"xccdf_org.ssgproject.content_rule_package_dnsmasq_removed",
		"xccdf_org.ssgproject.content_rule_package_bind_removed",
		"xccdf_org.ssgproject.content_rule_service_named_disabled",
	} {
		req := findBaselineRequirement(result.Requirements, rid)
		require.NotNil(t, req, "rule %s", rid)
		assert.Equal(t, ovalSystem, req.Tags["check_id"], "check_id for %s must prefer OVAL", rid)
	}
}

func TestSelectCheck(t *testing.T) {
	oval := Check{System: "http://oval.mitre.org/XMLSchema/oval-definitions-5"}
	ocil := Check{System: "http://scap.nist.gov/schema/ocil/2"}
	sce := Check{System: "http://open-scap.org/page/SCE"}
	disa := Check{System: "C-57723r848528_chk"}

	assert.Equal(t, oval.System, selectCheck([]Check{oval, ocil}).System, "OVAL over OCIL")
	assert.Equal(t, oval.System, selectCheck([]Check{sce, oval, ocil}).System, "OVAL over SCE/OCIL regardless of order")
	assert.Equal(t, sce.System, selectCheck([]Check{ocil, sce}).System, "automated SCE over manual OCIL")
	assert.Equal(t, disa.System, selectCheck([]Check{disa}).System, "single DISA check unchanged")
	assert.Equal(t, "", selectCheck(nil).System, "no checks → zero value")
}

func TestConvertXccdfBenchmarkToHDF_Groups(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	require.Len(t, result.Groups, 3)
	assert.Equal(t, "V-254238", result.Groups[0].ID)
	require.NotNil(t, result.Groups[0].Title)
	assert.Equal(t, "SRG-OS-000480-GPOS-00227", *result.Groups[0].Title)
	assert.Equal(t, []string{"SV-254238"}, result.Groups[0].Requirements)
}

func TestConvertXccdfBenchmarkToHDF_Generator(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "xccdf-results-to-hdf", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
}

func TestConvertXccdfBenchmarkToHDF_Checksum(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Integrity)
	require.NotNil(t, result.Integrity.Algorithm)
	assert.Equal(t, hdf.Sha256, *result.Integrity.Algorithm)
	require.NotNil(t, result.Integrity.Checksum)
	assert.Len(t, *result.Integrity.Checksum, 64)
}

func TestConvertXccdfBenchmarkToHDF_ErrorOnResults(t *testing.T) {
	// Results documents should produce a helpful error message
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "TestResult")
	assert.Contains(t, err.Error(), "xccdf-results")
}

func TestConvertXccdfBenchmarkToHDF_EmptyInput(t *testing.T) {
	result, err := ConvertXccdfBenchmarkToHDF([]byte{}, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertXccdfBenchmarkToHDF_NonXccdfInput(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><root><child>text</child></root>`)
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "not an XCCDF")
}

func TestConvertXccdfBenchmarkToHDF_Severity(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	req := findBaselineRequirement(result.Requirements, "SV-254238")
	require.NotNil(t, req)
	require.NotNil(t, req.Severity)
	assert.Equal(t, hdf.SeverityMedium, *req.Severity)

	highReq := findBaselineRequirement(result.Requirements, "SV-254240")
	require.NotNil(t, highReq)
	require.NotNil(t, highReq.Severity)
	assert.Equal(t, hdf.SeverityHigh, *highReq.Severity)
}

// --- ConvertXccdfToHDF auto-detect tests ---

func TestConvertXccdfToHDF_AutoDetectBenchmark(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	output, outputType, err := ConvertXccdfToHDF(input, converterVersion)
	require.NoError(t, err)
	assert.Equal(t, "baseline", outputType)
	assert.NotEmpty(t, output)

	// Verify it's valid baseline JSON
	var baseline hdf.HDFBaseline
	err = json.Unmarshal(output, &baseline)
	require.NoError(t, err)
	assert.Equal(t, "ms-windows-server-2022-stig", baseline.Name)
	assert.Len(t, baseline.Requirements, 3)
}

func TestConvertXccdfToHDF_AutoDetectResults(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	output, outputType, err := ConvertXccdfToHDF(input, converterVersion)
	require.NoError(t, err)
	assert.Equal(t, "results", outputType)
	assert.NotEmpty(t, output)

	// Verify it's valid results JSON
	var results hdf.HDFResults
	err = json.Unmarshal(output, &results)
	require.NoError(t, err)
	assert.Len(t, results.Baselines[0].Requirements, 5)
}

func TestConvertXccdfToHDF_AutoDetectARF(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	output, outputType, err := ConvertXccdfToHDF(input, converterVersion)
	require.NoError(t, err)
	assert.Equal(t, "results", outputType)
	assert.NotEmpty(t, output)
}

func TestConvertXccdfToHDF_EmptyInput(t *testing.T) {
	_, _, err := ConvertXccdfToHDF([]byte{}, converterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertXccdfToHDF_InvalidInput(t *testing.T) {
	_, _, err := ConvertXccdfToHDF([]byte("not xml"), converterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an XCCDF")
}

// --- Helper functions ---

func findBaselineRequirement(requirements []hdf.BaselineRequirement, id string) *hdf.BaselineRequirement {
	for i := range requirements {
		if requirements[i].ID == id {
			return &requirements[i]
		}
	}
	return nil
}

// --- extractRuleID tests ---

func TestExtractRuleID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard STIG rule ID", "SV-254238r991589_rule", "SV-254238"},
		{"qualified XCCDF rule ID", "xccdf_mil.disa.stig_rule_SV-204393r603261_rule", "SV-204393"},
		{"lowercase sv prefix", "sv-12345r67_rule", "SV-12345"},
		{"no revision suffix", "SV-12345", "SV-12345"},
		{"non-SV rule ID passthrough", "xccdf_moc.elpmaxe.www_rule_1", "xccdf_moc.elpmaxe.www_rule_1"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractRuleID(tt.input))
		})
	}
}

func TestConvertXccdfResultsToHDF_EmptyRuleResults(t *testing.T) {
	input := loadFixture(t, "empty.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "xccdf-results-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "XCCDF")
	assert.Contains(t, req.Results[0].CodeDesc, "empty-host.example.com")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

func TestConvertXccdfResultsToHDF_EmptyArfReport(t *testing.T) {
	arfXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<arf:asset-report-collection xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1" xmlns:core="http://scap.nist.gov/schema/reporting-core/1.1">
  <arf:reports>
    <arf:report id="xccdf1">
      <arf:content>
        <TestResult xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.open-scap_testresult_default-profile" start-time="2021-11-30T13:51:50+01:00" end-time="2021-11-30T13:51:50+01:00">
          <title>OSCAP Scan Result</title>
          <target>arf-empty-host</target>
        </TestResult>
      </arf:content>
    </arf:report>
  </arf:reports>
</arf:asset-report-collection>`)
	result, err := ConvertXccdfResultsToHDF(arfXML, converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "xccdf-results-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "XCCDF")
	assert.Contains(t, req.Results[0].CodeDesc, "arf-empty-host")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTestsRaw(t, "xccdf-results-to-hdf", func(input []byte) ([]byte, error) {
		output, _, err := ConvertXccdfToHDF(input, "1.0.0")
		return output, err
	})
}

func findDescription(descriptions []hdf.Description, label string) *hdf.Description {
	for i := range descriptions {
		if descriptions[i].Label == label {
			return &descriptions[i]
		}
	}
	return nil
}

// ---- Nested / multi-rule Group traversal ----

// Real SCAP Security Guide content nests Groups and puts many Rules in one
// Group. Modelling Group.Rule as a single element dropped every rule after the
// first, and omitting nested Groups dropped whole subtrees — together those
// silently discarded ~99% of the rules in an ssg-rhel8 benchmark.
//
// Fixture shape (verbatim from ComplianceAsCode v0.1.81, ssg-rhel8):
//
//	Benchmark
//	└── Group services
//	    └── Group dns                      (2 rules directly on the group)
//	        ├── Group disabling_dns_server (2 rules)
//	        └── Group dns_server_protection (3 rules)
func TestConvertXccdfBenchmark_NestedAndMultiRuleGroups(t *testing.T) {
	input := loadFixture(t, "benchmark-ssg-nested-groups.xml")

	baseline, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	ids := make([]string, 0, len(baseline.Requirements))
	for _, req := range baseline.Requirements {
		ids = append(ids, req.ID)
	}

	assert.Len(t, ids, 7, "every rule at every depth must survive")

	// Rules sitting directly on a Group that also has nested Groups.
	assert.Contains(t, ids, "xccdf_org.ssgproject.content_rule_package_dnsmasq_removed")
	assert.Contains(t, ids, "xccdf_org.ssgproject.content_rule_service_dnsmasq_disabled")
	// Rules from a nested Group holding 2 rules — the second proves we no longer
	// keep only the last rule of a group.
	assert.Contains(t, ids, "xccdf_org.ssgproject.content_rule_package_bind_removed")
	assert.Contains(t, ids, "xccdf_org.ssgproject.content_rule_service_named_disabled")
	// Rules from a sibling nested Group holding 3 rules.
	assert.Contains(t, ids, "xccdf_org.ssgproject.content_rule_dns_server_authenticate_zone_transfers")
	assert.Contains(t, ids, "xccdf_org.ssgproject.content_rule_dns_server_disable_dynamic_updates")
	assert.Contains(t, ids, "xccdf_org.ssgproject.content_rule_dns_server_disable_zone_transfers")
}

// A Group with N rules is one RequirementGroup listing N requirements, not N
// RequirementGroups each listing one.
func TestConvertXccdfBenchmark_GroupCarriesAllItsRules(t *testing.T) {
	input := loadFixture(t, "benchmark-ssg-nested-groups.xml")

	baseline, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	byID := make(map[string][]string)
	for _, g := range baseline.Groups {
		byID[g.ID] = g.Requirements
	}

	assert.Len(t, byID["xccdf_org.ssgproject.content_group_dns"], 2)
	assert.Len(t, byID["xccdf_org.ssgproject.content_group_disabling_dns_server"], 2)
	assert.Len(t, byID["xccdf_org.ssgproject.content_group_dns_server_protection"], 3)

	total := 0
	for _, reqs := range byID {
		total += len(reqs)
	}
	assert.Equal(t, 7, total, "no rule may be dropped or duplicated across groups")
}

// flattenGroups is the traversal both bugs came down to.
func TestFlattenGroups(t *testing.T) {
	groups := []Group{{
		ID:    "top",
		Rules: []Rule{{ID: "r1"}, {ID: "r2"}}, // multiple rules on one group
		Groups: []Group{{
			ID:    "nested",
			Rules: []Rule{{ID: "r3"}},
			Groups: []Group{{
				ID:    "deep",
				Rules: []Rule{{ID: "r4"}},
			}},
		}},
	}}

	got := make([]string, 0)
	for _, gr := range flattenGroups(groups) {
		got = append(got, gr.rule.ID+"@"+gr.group.ID)
	}

	assert.Equal(t, []string{"r1@top", "r2@top", "r3@nested", "r4@deep"}, got,
		"rules must be collected at every depth, with their owning group")
}

func TestFlattenGroups_SkipsRulesWithoutID(t *testing.T) {
	groups := []Group{{ID: "g", Rules: []Rule{{ID: ""}, {ID: "keep"}}}}
	got := flattenGroups(groups)
	require.Len(t, got, 1)
	assert.Equal(t, "keep", got[0].rule.ID)
}

// XCCDF severity is unknown|info|low|medium|high; HDF severity is
// critical|high|medium|low|informational. Casting the raw attribute straight
// across emitted schema-invalid HDF for the two XCCDF values HDF lacks.
func TestXccdfSeverityToHDF(t *testing.T) {
	tests := []struct {
		xccdf string
		want  *hdf.Severity
	}{
		{"high", hdfutil.Ptr(hdf.SeverityHigh)},
		{"medium", hdfutil.Ptr(hdf.SeverityMedium)},
		{"low", hdfutil.Ptr(hdf.SeverityLow)},
		{"HIGH", hdfutil.Ptr(hdf.SeverityHigh)}, // case-insensitive
		{"info", hdfutil.Ptr(hdf.Informational)},
		// "unknown" says severity was not determined. Omit it rather than assert
		// "informational", which would silently downgrade the rule.
		{"unknown", nil},
		{"", nil},
		{"bogus", nil},
	}

	for _, tt := range tests {
		t.Run(tt.xccdf, func(t *testing.T) {
			got := xccdfSeverityToHDF(tt.xccdf)
			if tt.want == nil {
				assert.Nil(t, got, "XCCDF severity %q has no HDF equivalent and must be omitted", tt.xccdf)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tt.want, *got)
		})
	}
}

// Real SSG rules carry severity="unknown"; the fixture must stay schema-valid.
func TestConvertXccdfBenchmark_UnknownSeverityOmitted(t *testing.T) {
	input := loadFixture(t, "benchmark-ssg-nested-groups.xml")

	baseline, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	bySeverity := map[string]int{}
	for _, req := range baseline.Requirements {
		if req.Severity == nil {
			bySeverity["<omitted>"]++
			continue
		}
		bySeverity[string(*req.Severity)]++
	}

	// The fixture holds 2 low, 3 medium, and 2 severity="unknown" rules.
	assert.Equal(t, 2, bySeverity["low"])
	assert.Equal(t, 3, bySeverity["medium"])
	assert.Equal(t, 2, bySeverity["<omitted>"], `severity="unknown" must not be emitted`)
	assert.Zero(t, bySeverity["unknown"], "raw XCCDF severity must never reach HDF")
}

// XCCDF prose elements are htmlTextWithSubType: CIS and SCAP Security Guide
// content carries its text inside XHTML children, so a parser that reads only
// an element's own character data drops every word. Text on both sides of the
// span proves document order is kept. Words are compared, not whitespace, which
// the prose readback tests pin against the source.
func TestConvertBenchmark_CarriesTextInsideXhtmlChildren(t *testing.T) {
	baseline, err := ConvertXccdfBenchmarkToHDF(loadFixture(t, "CIS_Google_Chrome_Benchmark_v2.1.0-xccdf.xml"), converterVersion)
	require.NoError(t, err)

	require.NotNil(t, baseline.Summary)
	require.True(t, strings.HasPrefix(words(*baseline.Summary), "This document provides prescriptive guidance for establishing a secure configuration posture for Google Chrome Browser."), "summary: %q", *baseline.Summary)

	const ruleID = "xccdf_org.cisecurity.benchmarks_rule_1.1.1_L1_Ensure_Cross-origin_HTTP_Authentication_prompts_is_set_to_Disabled"
	var req *hdf.BaselineRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == ruleID {
			req = &baseline.Requirements[i]
		}
	}
	require.NotNil(t, req, "rule 1.1.1 missing")

	descriptions := map[string]string{}
	for _, d := range req.Descriptions {
		descriptions[d.Label] = d.Data
	}
	require.Equal(t, "This setting controls whether third-party sub-content can open a HTTP Basic Auth dialog and is typically disabled. The recommended state for this setting is: Disabled (0)", words(descriptions["default"]))
	require.Equal(t, "This setting is typically disabled to help combat phishing attempts.", words(descriptions["rationale"]))
	require.Equal(t, `To establish the recommended configuration via GP, set the following UI path to Disabled : Computer Configuration\Policies\Administrative Templates\Google\Google Chrome\HTTP authentication\Cross-origin HTTP Authentication prompts Impact: None - This is the default behavior.`, words(descriptions["fix"]))
}

// words joins the whitespace-separated words of s with single spaces.
func words(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// The prose pipeline's edges, which no committed fixture carries: the five
// predefined entities and numeric references decode (DISA's escaped
// sub-elements depend on it) with an invalid code point becoming U+FFFD, a
// CDATA section is literal text, a comment or processing instruction is
// dropped even when it contains ">", a nested element keeps its place in the
// sentence, and every prose field (description, warning, rationale, fixtext)
// is wired. Synthetic XML input, not a committed fixture.
func TestConvertBenchmark_ProseEdges(t *testing.T) {
	input := []byte("<Benchmark xmlns=\"http://checklists.nist.gov/xccdf/1.2\" xmlns:xhtml=\"http://www.w3.org/1999/xhtml\" id=\"xccdf_x_benchmark_p\">" +
		"<status>draft</status><title>t</title><version>1</version>" +
		"<Group id=\"g\"><title>g</title><Rule id=\"r\" severity=\"low\"><title>r</title>" +
		"<description>a &lt;b&gt; &amp; &#65; &#x42; &quot;q&quot; &apos;p&apos; &#xD800; line1\r\nline2 <xhtml:p>in <xhtml:s>s</xhtml:s> out</xhtml:p> <!-- c > d --> <?pi x > y ?> <![CDATA[c &amp; <d>]]> end</description>" +
		"<warning category=\"general\"><xhtml:p>careful <xhtml:code>x</xhtml:code></xhtml:p></warning>" +
		"<rationale><xhtml:p>why <xhtml:em>it</xhtml:em> matters</xhtml:p></rationale>" +
		"<fixtext fixref=\"f\"><xhtml:div>run <xhtml:code>cmd</xhtml:code></xhtml:div></fixtext>" +
		"</Rule></Group></Benchmark>")
	baseline, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)
	require.Len(t, baseline.Requirements, 1)
	descriptions := map[string]string{}
	for _, d := range baseline.Requirements[0].Descriptions {
		descriptions[d.Label] = d.Data
	}
	require.Equal(t, map[string]string{
		"default":   "a  & A B \"q\" 'p' \uFFFD line1\nline2 in s out   c &amp;  end",
		"fix":       "run cmd",
		"rationale": "why it matters",
		"warning":   "careful x",
	}, descriptions)
}

// --- Benchmark-level facts under extensions.passthrough ---

func baselineOf(t *testing.T, fixture string) *hdf.HDFBaseline {
	t.Helper()
	baseline, err := ConvertXccdfBenchmarkToHDF(loadFixture(t, fixture), converterVersion)
	require.NoError(t, err)
	return baseline
}

func passthroughOf(t *testing.T, baseline *hdf.HDFBaseline) map[string]any {
	t.Helper()
	require.NotNil(t, baseline.Extensions, "extensions missing")
	return baseline.Extensions.Passthrough
}

// DISA's release-info, located by id and split on "Benchmark Date: ".
func TestConvertBenchmark_ReleaseInfo(t *testing.T) {
	ext := passthroughOf(t, baselineOf(t, "U_RHEL_9_STIG_V2R9_Manual-xccdf.xml"))
	require.Equal(t, "Release: 9 Benchmark Date: 01 Jul 2026", ext["releaseInfo"])
	require.Equal(t, "9", ext["benchmarkRelease"])
	require.Equal(t, "01 Jul 2026", ext["benchmarkDate"])
}

func TestConvertBenchmark_PassthroughCarriesBenchmarkFacts(t *testing.T) {
	disaBaseline := baselineOf(t, "U_RHEL_9_STIG_V2R9_Manual-xccdf.xml")
	disa := passthroughOf(t, disaBaseline)
	require.Equal(t, "accepted", disa["benchmarkStatus"])
	require.Equal(t, "2026-05-20", disa["benchmarkStatusDate"])
	require.Equal(t, "DISA", disa["publisher"])
	require.Equal(t, "STIG.DOD.MIL", disa["source"])
	require.Equal(t, "3.5.2", disa["generatorVersion"])
	require.Equal(t, "1.10.0", disa["conventionsVersion"])
	require.Equal(t, []map[string]any{{"id": "terms-of-use", "text": ""}}, disa["notices"])
	require.NotContains(t, disa, "platforms")
	disaProfiles, ok := disa["profiles"].([]map[string]any)
	require.True(t, ok, "profiles: %T", disa["profiles"])
	require.Len(t, disaProfiles, 9)
	require.Equal(t, map[string]any{
		"id":              "MAC-1_Classified",
		"selectedRuleIds": []string{"SV-257777", "SV-257778", "SV-257779", "SV-257782", "SV-257784", "SV-257795", "SV-257949"},
		"title":           "I - Mission Critical Classified",
	}, disaProfiles[0])

	cisBaseline := baselineOf(t, "CIS_Google_Chrome_Benchmark_v2.1.0-xccdf.xml")
	cis := passthroughOf(t, cisBaseline)
	require.Equal(t, "draft", cis["benchmarkStatus"])
	require.Equal(t, "2021-12-09", cis["benchmarkStatusDate"])
	require.Equal(t, []string{"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*"}, cis["platforms"])
	for _, absent := range []string{"releaseInfo", "benchmarkRelease", "benchmarkDate", "publisher", "source", "generatorVersion", "conventionsVersion"} {
		require.NotContains(t, cis, absent)
	}
	cisNotices, ok := cis["notices"].([]map[string]any)
	require.True(t, ok, "notices: %T", cis["notices"])
	require.Len(t, cisNotices, 1)
	require.Equal(t, "terms-of-use", cisNotices[0]["id"])
	noticeText, ok := cisNotices[0]["text"].(string)
	require.True(t, ok, "notice text: %T", cisNotices[0]["text"])
	require.True(t, strings.HasPrefix(noticeText, "BACKGROUND. The Center for Internet Security"), "notice text: %q", noticeText)
	cisProfiles, ok := cis["profiles"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, cisProfiles, 2)
	require.Equal(t, "xccdf_org.cisecurity.benchmarks_profile_Level_1_L1_-_CorporateEnterprise_Environment_general_use", cisProfiles[0]["id"])
	require.Equal(t, "Level 1 (L1) - Corporate/Enterprise Environment (general use)", cisProfiles[0]["title"])
	level1, ok := cisProfiles[0]["selectedRuleIds"].([]string)
	require.True(t, ok)
	require.Len(t, level1, 15)
	require.Equal(t, "xccdf_org.cisecurity.benchmarks_rule_1.1.1_L1_Ensure_Cross-origin_HTTP_Authentication_prompts_is_set_to_Disabled", level1[0])
	require.Len(t, cisProfiles[1]["selectedRuleIds"], 23)

	for name, baseline := range map[string]*hdf.HDFBaseline{"disa": disaBaseline, "cis": cisBaseline} {
		data, err := json.Marshal(baseline)
		require.NoError(t, err)
		result := hdfvalidators.ValidateBaseline(data)
		require.True(t, result.Valid, "%s baseline with passthrough does not validate: %s", name, result.Error())
	}
}

func TestParseReleaseInfo(t *testing.T) {
	for _, c := range []struct {
		in, release, date string
		ok                bool
	}{
		{"Release: 9 Benchmark Date: 01 Jul 2026", "9", "01 Jul 2026", true},
		{"Release: 3.5 Benchmark Date: 24 Jan 2020", "3.5", "24 Jan 2020", true},
		{"Release: 12 Benchmark Date: 23 Oct 2020 ", "12", "23 Oct 2020", true},
		{"Version 2 build 7", "", "", false},
		{"Benchmark Date: 01 Jul 2026", "", "", false},
		{"Release: 9 Benchmark Date: ", "", "", false},
		{"", "", "", false},
	} {
		release, date, ok := parseReleaseInfo(c.in)
		require.Equal(t, c.ok, ok, c.in)
		require.Equal(t, c.release, release, c.in)
		require.Equal(t, c.date, date, c.in)
	}
}

// release-info is found by its id wherever it sits among the plain-text
// elements, and unparseable text keeps releaseInfo verbatim with no parsed
// keys and no error. Synthetic XML input, not a committed fixture.
func TestConvertBenchmark_ReleaseInfoByIdAndUnparseable(t *testing.T) {
	head := "<Benchmark xmlns=\"http://checklists.nist.gov/xccdf/1.1\" id=\"x_benchmark\"><status date=\"2026-01-02\">accepted</status><title>t</title><description>d</description>"
	tail := "<version>1</version><Group id=\"V-1\"><title>g</title><Rule id=\"SV-1r1_rule\" severity=\"low\"><version>X-1</version><title>r</title><description>d</description></Rule></Group></Benchmark>"

	byID, err := ConvertXccdfBenchmarkToHDF([]byte(head+
		"<plain-text id=\"other\">Release: 1 Benchmark Date: 01 Jan 2000</plain-text><plain-text id=\"generator\">3.5.2</plain-text><plain-text id=\"conventionsVersion\">1.10.0</plain-text><plain-text id=\"release-info\">Release: 4 Benchmark Date: 02 Feb 2026</plain-text>"+tail), converterVersion)
	require.NoError(t, err)
	ext := passthroughOf(t, byID)
	require.Equal(t, "Release: 4 Benchmark Date: 02 Feb 2026", ext["releaseInfo"])
	require.Equal(t, "4", ext["benchmarkRelease"])
	require.Equal(t, "02 Feb 2026", ext["benchmarkDate"])
	require.Equal(t, "3.5.2", ext["generatorVersion"])
	require.Equal(t, "1.10.0", ext["conventionsVersion"])

	unparseable, err := ConvertXccdfBenchmarkToHDF([]byte(head+"<plain-text id=\"release-info\">Version 2 build 7</plain-text>"+tail), converterVersion)
	require.NoError(t, err)
	ext = passthroughOf(t, unparseable)
	require.Equal(t, "Version 2 build 7", ext["releaseInfo"])
	require.NotContains(t, ext, "benchmarkRelease")
	require.NotContains(t, ext, "benchmarkDate")

	none, err := ConvertXccdfBenchmarkToHDF([]byte(head+tail), converterVersion)
	require.NoError(t, err)
	ext = passthroughOf(t, none)
	for _, absent := range []string{"releaseInfo", "benchmarkRelease", "benchmarkDate", "generatorVersion", "conventionsVersion", "notices", "platforms", "profiles", "publisher", "source"} {
		require.NotContains(t, ext, absent)
	}
	require.Equal(t, "accepted", ext["benchmarkStatus"])
}

// A Profile select names a Rule or a Group. A selected Group contributes every
// rule it holds at any depth unless that rule or an inner group opts out
// (XCCDF: selecting a Group selects its items), so selectedRuleIds always
// holds requirement ids a consumer can join on. Duplicates collapse; an idref
// naming nothing is kept as given. Synthetic XML input, not a committed fixture.
func TestConvertBenchmark_ProfileSelectsResolveToRequirementIDs(t *testing.T) {
	input := []byte("<Benchmark xmlns=\"http://checklists.nist.gov/xccdf/1.1\" id=\"x_benchmark\"><status>accepted</status><title>t</title><description>d</description><version>1</version>" +
		"<Profile id=\"p\"><title>P</title><select idref=\"g1\" selected=\"true\"/><select idref=\"SV-3r1_rule\" selected=\"true\"/><select idref=\"nothing\" selected=\"true\"/><select idref=\"SV-5r1_rule\" selected=\"false\"/></Profile>" +
		"<Group id=\"g1\"><title>g1</title><Rule id=\"SV-1r1_rule\" severity=\"low\"><version>X-1</version><title>r1</title><description>d</description></Rule>" +
		"<Group id=\"g2\"><title>g2</title><Rule id=\"SV-2r1_rule\" severity=\"low\" selected=\"false\"><version>X-2</version><title>r2</title><description>d</description></Rule><Rule id=\"SV-3r1_rule\" severity=\"low\"><version>X-3</version><title>r3</title><description>d</description></Rule></Group>" +
		"<Group id=\"g3\" selected=\"false\"><title>g3</title><Rule id=\"SV-4r1_rule\" severity=\"low\"><version>X-4</version><title>r4</title><description>d</description></Rule></Group></Group>" +
		"<Group id=\"g4\"><title>g4</title><Rule id=\"SV-5r1_rule\" severity=\"low\"><version>X-5</version><title>r5</title><description>d</description></Rule></Group></Benchmark>")
	baseline, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)
	profiles, ok := passthroughOf(t, baseline)["profiles"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, profiles, 1)
	require.Equal(t, []string{"SV-1", "SV-3", "nothing"}, profiles[0]["selectedRuleIds"])
}

// Edges no fixture carries, resolved alike in both languages: several status
// elements (latest dated wins; undated, the last), attributed Dublin Core
// children, first non-empty publisher and source, a Profile with several titles
// (the first), selected="0", a dangling revisioned idref, a notice with markup.
// Synthetic XML input, not a committed fixture.
func TestConvertBenchmark_PassthroughEdges(t *testing.T) {
	rule := "<Group id=\"g\"><title>g</title><Rule id=\"SV-1r1_rule\" severity=\"low\"><version>X-1</version><title>r1</title><description>d</description></Rule><Rule id=\"SV-2r1_rule\" severity=\"low\"><version>X-2</version><title>r2</title><description>d</description></Rule></Group></Benchmark>"
	input := []byte("<Benchmark xmlns=\"http://checklists.nist.gov/xccdf/1.1\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xhtml=\"http://www.w3.org/1999/xhtml\" id=\"x_benchmark\">" +
		"<status date=\"2021-02-02\">accepted</status><status date=\"2020-01-01\">draft</status><status>incomplete</status>" +
		"<title>t</title><description>d</description>" +
		"<notice id=\"n\"><xhtml:p>a <xhtml:b>b</xhtml:b></xhtml:p></notice>" +
		"<reference href=\"https://example.invalid\"><dc:publisher></dc:publisher><dc:source>S1</dc:source></reference>" +
		"<reference><dc:publisher xml:lang=\"en\">P2</dc:publisher><dc:publisher>P2b</dc:publisher><dc:source>S2</dc:source></reference>" +
		"<reference><dc:publisher>P3</dc:publisher></reference>" +
		"<version>1</version>" +
		"<Profile id=\"p\"><title xml:lang=\"en\">First</title><title xml:lang=\"de\">Zweite</title><select idref=\"SV-1r1_rule\" selected=\"true\"/><select idref=\"SV-2r1_rule\" selected=\" 0 \"/><select idref=\"SV-9r2_rule\" selected=\"true\"/></Profile>" + rule)
	baseline, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)
	require.Equal(t, map[string]any{
		"benchmarkStatus":     "accepted",
		"benchmarkStatusDate": "2021-02-02",
		"notices":             []map[string]any{{"id": "n", "text": "a b"}},
		"profiles":            []map[string]any{{"id": "p", "selectedRuleIds": []string{"SV-1", "SV-9"}, "title": "First"}},
		"publisher":           "P2",
		"source":              "S1",
	}, passthroughOf(t, baseline))

	undated, err := ConvertXccdfBenchmarkToHDF([]byte("<Benchmark xmlns=\"http://checklists.nist.gov/xccdf/1.1\" id=\"x_benchmark\"><status>draft</status><status>accepted</status><title>t</title><description>d</description><version>1</version>"+rule), converterVersion)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"benchmarkStatus": "accepted"}, passthroughOf(t, undated))
}

// TestRuleResultDispositions pins every rule-result the status map distinguishes.
// The two dispositions that leave the compliance denominator are the point: a
// deselected rule was never meant to be assessed, and an informational one
// produces no verdict to score, while notchecked IS outstanding work and stays
// in. Impact is the rule's real severity throughout — the disposition travels in
// the status, never by zeroing a severity.
func TestRuleResultDispositions(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "rule-result-dispositions.xml"))
	require.NoError(t, err)
	out, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	byID := map[string]*hdf.EvaluatedRequirement{}
	for i := range out.Baselines[0].Requirements {
		r := &out.Baselines[0].Requirements[i]
		byID[r.ID] = r
	}

	for _, tc := range []struct {
		rule       string
		wantStatus hdf.ResultStatus
		wantImpact float64
	}{
		{"xccdf_org.mitre.hdf_rule_pass", hdf.Passed, 0.5},
		{"xccdf_org.mitre.hdf_rule_fail", hdf.Failed, 0.7},
		// Out of scope for this profile, so excluded from the ratio — and still a
		// high-severity rule, which is why impact is 0.7 and not zeroed.
		{"xccdf_org.mitre.hdf_rule_notselected", hdf.NotApplicable, 0.7},
		{"xccdf_org.mitre.hdf_rule_notapplicable", hdf.NotApplicable, 0.5},
		// No automated check means someone must still check it: outstanding work.
		{"xccdf_org.mitre.hdf_rule_notchecked", hdf.NotReviewed, 0.3},
		{"xccdf_org.mitre.hdf_rule_informational", hdf.NotApplicable, 0.0},
		// An info-severity rule that failed still failed; severity is not status.
		{"xccdf_org.mitre.hdf_rule_info_severity_fail", hdf.Failed, 0.0},
	} {
		t.Run(tc.rule, func(t *testing.T) {
			req := byID[tc.rule]
			require.NotNil(t, req, "requirement %s missing from the output", tc.rule)
			require.Len(t, req.Results, 1)
			assert.Equal(t, tc.wantStatus, req.Results[0].Status)
			assert.InDelta(t, tc.wantImpact, req.Impact, 0.0001,
				"impact is the rule's severity; the disposition belongs to the status")
		})
	}
}

// TestRuleResultDispositions_ComplianceDenominator states the consequence the
// ruling turns on: the deselected and informational rules must sit outside the
// ratio, so a benchmark's unselected tail cannot drag the published number down.
func TestRuleResultDispositions_ComplianceDenominator(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "rule-result-dispositions.xml"))
	require.NoError(t, err)
	out, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	counts := map[hdf.ResultStatus]int{}
	for _, req := range out.Baselines[0].Requirements {
		for _, res := range req.Results {
			counts[res.Status]++
		}
	}
	assert.Equal(t, 1, counts[hdf.Passed])
	assert.Equal(t, 2, counts[hdf.Failed])
	assert.Equal(t, 1, counts[hdf.NotReviewed], "only notchecked remains outstanding work")
	assert.Equal(t, 3, counts[hdf.NotApplicable],
		"notselected, notapplicable and informational all leave the denominator")
}
