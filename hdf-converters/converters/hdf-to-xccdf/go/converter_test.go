package hdftoxccdf

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err, "Failed to load fixture: %s", name)
	return data
}

// --- Minimal round-trip tests ---

func TestConvertHDFToXCCDF_FieldCoverage(t *testing.T) {
	input := []byte(`{"baselines":[{"name":"b","requirements":[{
		"id":"SV-1","impact":0.7,"title":"req",
		"tags":{"nist":["AC-2"],"cci":["CCI-000012"]},
		"descriptions":[{"label":"default","data":"d"},{"label":"check","data":"check text"},{"label":"rationale","data":"rationale text"}],
		"code":"control 'SV-1' do end",
		"refs":[{"url":"https://example.gov/a"},{"ref":"Handbook 3"}],
		"results":[{"status":"failed","codeDesc":"c","startTime":"2026-01-01T00:00:00Z"}]
	}]}]}`)
	output, err := ConvertHDFToXCCDF(input, "test")
	require.NoError(t, err)
	result := string(output)
	assert.Contains(t, result, "<rationale>rationale text</rationale>")
	assert.Contains(t, result, `href="https://example.gov/a"`)
	assert.Contains(t, result, "Handbook 3")
	assert.Contains(t, result, "csrc.nist.gov") // NIST ident system
	assert.Contains(t, result, ">AC-2<")
	assert.Contains(t, result, "http://inspec.io/") // code emitted as its own <check>
}

func TestConvertHDFToXCCDF_Minimal(t *testing.T) {
	input := loadFixture(t, "minimal.json")

	output, err := ConvertHDFToXCCDF(input, "test")
	require.NoError(t, err)
	require.NotEmpty(t, output)

	result := string(output)

	// XML declaration
	assert.True(t, strings.HasPrefix(result, "<?xml"), "Should start with XML declaration")

	// Benchmark root element
	assert.Contains(t, result, `xmlns="http://checklists.nist.gov/xccdf/1.2"`)
	assert.Contains(t, result, `<Benchmark`)
	assert.Contains(t, result, `</Benchmark>`)

	// Benchmark metadata
	assert.Contains(t, result, `resolved="1"`)

	// Rules present
	assert.Contains(t, result, `<Rule`)
	assert.Contains(t, result, `xccdf_hdf_rule_xccdf_moc.elpmaxe.www_rule_1_rule`)
	assert.Contains(t, result, `xccdf_hdf_rule_xccdf_moc.elpmaxe.www_rule_2_rule`)

	// TestResult present
	assert.Contains(t, result, `<TestResult`)
	assert.Contains(t, result, `<target>Test Target</target>`)

	// Rule results
	assert.Contains(t, result, `<result>fail</result>`)
	assert.Contains(t, result, `<result>pass</result>`)

	// Valid XML
	var benchmark XCCDFBenchmark
	err = xml.Unmarshal(output, &benchmark)
	assert.NoError(t, err, "Output should be valid XML")
}

func TestConvertHDFToXCCDF_StigRhel7(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.json")

	output, err := ConvertHDFToXCCDF(input, "test")
	require.NoError(t, err)
	require.NotEmpty(t, output)

	result := string(output)

	// CCI idents preserved
	assert.Contains(t, result, `system="http://cyber.mil/cci"`)
	assert.Contains(t, result, `CCI-000048`)
	assert.Contains(t, result, `CCI-000366`)

	// Severities mapped correctly
	assert.Contains(t, result, `severity="medium"`)
	assert.Contains(t, result, `severity="high"`)
	assert.Contains(t, result, `severity="low"`)

	// Target info preserved
	assert.Contains(t, result, `<target>localhost.localdomain</target>`)
	assert.Contains(t, result, `<target-address>127.0.0.1</target-address>`)

	// Timestamps preserved
	assert.Contains(t, result, `2021-12-17`)

	// Fix text preserved
	assert.Contains(t, result, `<fixtext>`)

	// Valid XML
	var benchmark XCCDFBenchmark
	err = xml.Unmarshal(output, &benchmark)
	require.NoError(t, err)
	// STIG rules carry gid/gtitle tags, so each is nested in its own Group.
	assert.Equal(t, 5, len(collectRules(benchmark)))
	assert.Equal(t, 5, len(benchmark.TestResult.RuleResults))
}

// collectRules returns every Rule in the benchmark, whether nested in a Group or
// flat under the Benchmark.
func collectRules(b XCCDFBenchmark) []XCCDFRule {
	rules := append([]XCCDFRule(nil), b.Rules...)
	for _, g := range b.Groups {
		rules = append(rules, g.Rules...)
	}
	return rules
}

// --- Status mapping tests ---

func TestHdfStatusToXCCDF(t *testing.T) {
	tests := []struct {
		hdf   hdf.ResultStatus
		xccdf string
	}{
		{hdf.Passed, "pass"},
		{hdf.Failed, "fail"},
		{hdf.Error, "error"},
		{hdf.NotReviewed, "notchecked"},
		{hdf.NotApplicable, "notapplicable"},
	}

	for _, tt := range tests {
		t.Run(string(tt.hdf), func(t *testing.T) {
			assert.Equal(t, tt.xccdf, hdfStatusToXCCDF(tt.hdf))
		})
	}
}

// --- Impact mapping tests ---

func TestImpactToSeverity(t *testing.T) {
	tests := []struct {
		impact   float64
		severity string
	}{
		{0.9, "high"},
		{0.7, "high"},
		{0.5, "medium"},
		{0.4, "medium"},
		{0.3, "low"},
		{0.1, "low"},
		{0.0, "info"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			assert.Equal(t, tt.severity, impactToSeverity(tt.impact))
		})
	}
}

// --- Error handling tests ---

func TestConvertHDFToXCCDF_InvalidJSON(t *testing.T) {
	_, err := ConvertHDFToXCCDF([]byte("not json"), "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid HDF JSON")
}

func TestConvertHDFToXCCDF_EmptyInput(t *testing.T) {
	_, err := ConvertHDFToXCCDF([]byte(""), "test")
	require.Error(t, err)
}

func TestConvertHDFToXCCDF_MissingBaselines(t *testing.T) {
	_, err := ConvertHDFToXCCDF([]byte(`{"foo": "bar"}`), "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing baselines")
}

func TestConvertHDFToXCCDF_EmptyBaselines(t *testing.T) {
	input := []byte(`{
		"baselines": [],
		"components": [],
		"statistics": {}
	}`)

	output, err := ConvertHDFToXCCDF(input, "test")
	require.NoError(t, err)
	require.NotEmpty(t, output)

	var benchmark XCCDFBenchmark
	err = xml.Unmarshal(output, &benchmark)
	require.NoError(t, err)
	assert.Equal(t, "xccdf_hdf_benchmark_exported", benchmark.ID)
}

// --- sanitizeXCCDFID tests ---

func TestSanitizeXCCDFID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple_id", "simple_id"},
		{"id with spaces", "id_with_spaces"},
		{"id/with/slashes", "id_with_slashes"},
		{"RHEL-07-010030", "RHEL-07-010030"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, sanitizeXCCDFID(tt.input))
		})
	}
}

// --- Round-trip structural tests ---

func TestConvertHDFToXCCDF_RoundTrip_RuleCount(t *testing.T) {
	input := loadFixture(t, "minimal.json")

	output, err := ConvertHDFToXCCDF(input, "test")
	require.NoError(t, err)

	var benchmark XCCDFBenchmark
	err = xml.Unmarshal(output, &benchmark)
	require.NoError(t, err)

	// minimal.json has 2 requirements → 2 rules
	assert.Equal(t, 2, len(benchmark.Rules))
	// 2 rule-results (one per requirement)
	assert.Equal(t, 2, len(benchmark.TestResult.RuleResults))
}

func TestConvertHDFToXCCDF_RoundTrip_SeverityMapping(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.json")

	output, err := ConvertHDFToXCCDF(input, "test")
	require.NoError(t, err)

	var benchmark XCCDFBenchmark
	err = xml.Unmarshal(output, &benchmark)
	require.NoError(t, err)

	// RHEL-07-010290 has impact 0.7 → high
	// RHEL-07-020200 has impact 0.3 → low
	// Others have impact 0.5 → medium
	severityCounts := map[string]int{}
	for _, rule := range collectRules(benchmark) {
		severityCounts[rule.Severity]++
	}
	assert.Equal(t, 3, severityCounts["medium"])
	assert.Equal(t, 1, severityCounts["high"])
	assert.Equal(t, 1, severityCounts["low"])
}

func TestConvertHDFToXCCDF_SpecialCharacters(t *testing.T) {
	input := []byte(`{
		"baselines": [{
			"name": "Test & <Special>",
			"requirements": [{
				"id": "REQ-001",
				"title": "Rule with <angle> & \"quotes\"",
				"descriptions": [{"label": "default", "data": "Description with & and <"}],
				"impact": 0.5,
				"tags": {},
				"results": [{"codeDesc": "Test", "startTime": "2025-01-01T00:00:00Z", "status": "passed"}]
			}]
		}],
		"statistics": {}
	}`)

	output, err := ConvertHDFToXCCDF(input, "test")
	require.NoError(t, err)

	// Should be valid XML (encoding/xml handles escaping)
	var benchmark XCCDFBenchmark
	err = xml.Unmarshal(output, &benchmark)
	require.NoError(t, err)

	assert.Equal(t, 1, len(benchmark.Rules))
	assert.Equal(t, `Rule with <angle> & "quotes"`, benchmark.Rules[0].Title)
}

// --- Export-fidelity value pins (fields the export formerly dropped) ---

func TestConvertHDFToXCCDF_BenchmarkDescription(t *testing.T) {
	out, err := ConvertHDFToXCCDF(loadFixture(t, "stig-rhel7.json"), "test")
	require.NoError(t, err)
	var benchmark XCCDFBenchmark
	require.NoError(t, xml.Unmarshal(out, &benchmark))
	// baseline.summary -> Benchmark/description.
	assert.Contains(t, benchmark.Description, "Security Technical Implementation Guide is published")
}

func TestConvertHDFToXCCDF_EndTimeCarriesDuration(t *testing.T) {
	out, err := ConvertHDFToXCCDF(loadFixture(t, "stig-rhel7.json"), "test")
	require.NoError(t, err)
	var benchmark XCCDFBenchmark
	require.NoError(t, xml.Unmarshal(out, &benchmark))
	// timestamp 2021-12-17T10:39:29Z + statistics.duration 89s = 10:40:58Z.
	assert.Equal(t, "2021-12-17T10:39:29Z", benchmark.TestResult.StartTime)
	assert.Equal(t, "2021-12-17T10:40:58Z", benchmark.TestResult.EndTime)
	assert.NotEqual(t, benchmark.TestResult.StartTime, benchmark.TestResult.EndTime,
		"end-time must not collapse to start-time or duration is lost on round-trip")
}

func TestConvertHDFToXCCDF_StigTagsAndGroups(t *testing.T) {
	out, err := ConvertHDFToXCCDF(loadFixture(t, "stig-rhel7.json"), "test")
	require.NoError(t, err)
	var benchmark XCCDFBenchmark
	require.NoError(t, xml.Unmarshal(out, &benchmark))

	require.Equal(t, 5, len(benchmark.Groups), "one Group per gid tag")
	require.Empty(t, benchmark.Rules, "grouped rules must not also appear flat")

	// First rule: SV-204393 / RHEL-07-010030 with its STIG identifiers.
	g := benchmark.Groups[0]
	assert.Equal(t, "xccdf_mil.disa.stig_group_V-204393", g.ID)
	assert.Equal(t, "SRG-OS-000023-GPOS-00006", g.Title)
	require.Equal(t, 1, len(g.Rules))
	rule := g.Rules[0]
	assert.Equal(t, "RHEL-07-010030", rule.Version, "stig_id -> Rule/version")

	idents := map[string][]string{}
	for _, id := range rule.Idents {
		idents[id.System] = append(idents[id.System], id.Value)
	}
	assert.Equal(t, []string{"CCI-000048"}, idents["http://cyber.mil/cci"])
	assert.Equal(t, []string{"CCE-26970-4"}, idents["http://cce.mitre.org"], "cce -> ident cce.mitre.org")
	assert.Equal(t, []string{"V-71859", "SV-86483"}, idents["http://cyber.mil/legacy"], "legacy_id -> ident cyber.mil/legacy")

	// rule-result carries the STIG ID in @version too (importer prefers it).
	assert.Equal(t, "RHEL-07-010030", benchmark.TestResult.RuleResults[0].Version)
}

func TestConvertHDFToXCCDF_TestSystemFromTool(t *testing.T) {
	out, err := ConvertHDFToXCCDF(loadFixture(t, "stig-rhel7.json"), "test")
	require.NoError(t, err)
	var benchmark XCCDFBenchmark
	require.NoError(t, xml.Unmarshal(out, &benchmark))
	// tool {name:XCCDF, version:1.2.17} -> CPE whose 4th field is the version.
	assert.Equal(t, "cpe:/a:xccdf:xccdf:1.2.17", benchmark.TestResult.TestSystem)
}

func TestConvertHDFToXCCDF_EffectiveStatusGovernsResult(t *testing.T) {
	// A waiver flips a failed result to notApplicable via effectiveStatus; the
	// emitted rule-result must reflect the effective (post-override) status.
	input := []byte(`{"baselines":[{"name":"b","requirements":[{
		"id":"SV-1","impact":0.5,"title":"req","tags":{},
		"descriptions":[{"label":"default","data":"d"}],
		"effectiveStatus":"notApplicable",
		"results":[{"status":"failed","codeDesc":"c","startTime":"2026-01-01T00:00:00Z"}]
	}]}]}`)
	out, err := ConvertHDFToXCCDF(input, "test")
	require.NoError(t, err)
	result := string(out)
	assert.Contains(t, result, "<result>notapplicable</result>")
	assert.NotContains(t, result, "<result>fail</result>")
}

func TestConvertHDFToXCCDF_RawStatusWhenNoOverride(t *testing.T) {
	input := []byte(`{"baselines":[{"name":"b","requirements":[{
		"id":"SV-1","impact":0.5,"title":"req","tags":{},
		"descriptions":[{"label":"default","data":"d"}],
		"results":[{"status":"failed","codeDesc":"c","startTime":"2026-01-01T00:00:00Z"}]
	}]}]}`)
	out, err := ConvertHDFToXCCDF(input, "test")
	require.NoError(t, err)
	assert.Contains(t, string(out), "<result>fail</result>")
}

// TestGoldenParity asserts whole-output equality against frozen golden XCCDF
// documents built from the converter's real HDF inputs. The TypeScript test
// asserts the SAME files under the SAME normalization, so the two
// implementations cannot drift apart. Run with UPDATE_GOLDEN=1 to rewrite.
func TestGoldenParity(t *testing.T) {
	for _, name := range []string{"minimal", "stig-rhel7"} {
		out, err := ConvertHDFToXCCDF(loadFixture(t, name+".json"), "test")
		require.NoError(t, err, "convert %s", name)

		goldenPath := filepath.Join("..", "fixtures", "expected", name+".xccdf")
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0o755))
			require.NoError(t, os.WriteFile(goldenPath, out, 0o644)) //nolint:gosec // test golden
			continue
		}
		golden, err := os.ReadFile(goldenPath)
		require.NoError(t, err, "read golden %s", goldenPath)
		assert.Equal(t, shared.NormalizeXMLForGolden(string(golden)), shared.NormalizeXMLForGolden(string(out)),
			"golden mismatch for %s", name)
	}
}
