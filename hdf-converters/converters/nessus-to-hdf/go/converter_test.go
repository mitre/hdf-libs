package nessus

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "1.0.0"

func TestConvertNessusToHDF_Sample(t *testing.T) {
	// Load real Nessus scan fixture
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "sample.nessus")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read sample.nessus fixture")

	// Convert
	result, err := ConvertNessusToHDF(inputData, converterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Verify basic structure
	assert.Equal(t, "nessus-to-hdf", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
	assert.Len(t, result.Baselines, 3, "Should have 3 baselines (one per scanned host)")
	assert.Len(t, result.Components, 3, "Should have 3 targets (3 scanned hosts)")

	// Verify each baseline has requirements
	for _, baseline := range result.Baselines {
		assert.Equal(t, "Nessus Basic Network Scan", baseline.Name)
		assert.Greater(t, len(baseline.Requirements), 0, "Should have requirements")
	}

	// Write output for differential testing
	shared.WriteOutput(t, "nessus-to-hdf", "sample.json", result)
}

// Ground-truth anchor (input-derived count; see shared/go/anchor.go). Golden
// parity proves Go and TS agree, not that either is correct. Nessus emits one
// requirement per <ReportItem>; assert that count derived INDEPENDENTLY from the
// source, so a silent under-extraction fails even when both languages agree.
func TestConvertNessusToHDF_ReportItemAnchor(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "sample.nessus")
	input, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertNessusToHDF(input, converterVersion)
	require.NoError(t, err)

	want := shared.CountXMLElements(t, input, "ReportItem")
	shared.AssertRequirementCount(t, result, want,
		"sample.nessus: one requirement per <ReportItem>")
}

// TestConvertNessusToHDF_ACASFieldsPreserved locks in that ACAS / Tenable.sc-shape
// fields survive conversion. ACAS emits the same NessusClientData_v2 schema as
// standalone Nessus and differs only by which optional fields are populated, so
// sample.nessus (a real scan that happens to carry them) is the standing ACAS
// regression guard. cvss3_base_score is promoted to a structured tag and cvss[]
// entry; the IAVM (IAVA/IAVB) xref and stig_severity (STIG CAT) are preserved in
// the raw code blob — promoting those two to first-class tags is tracked as
// separate follow-up work.
func TestConvertNessusToHDF_ACASFieldsPreserved(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "sample.nessus")
	input, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertNessusToHDF(input, converterVersion)
	require.NoError(t, err)

	var reqs []hdf.EvaluatedRequirement
	for _, b := range result.Baselines {
		reqs = append(reqs, b.Requirements...)
	}

	// Plugin 156888 (Oracle Java Jan-2022 CPU) is an ACAS-shaped finding: it
	// carries a CVSS v3 base score, an IAVA xref, and a STIG CAT together.
	req := shared.MustFindRequirement(t, reqs, "156888")

	// CVSS v3 is promoted to structured HDF (tag + cvss[] entry), not dropped.
	assert.Equal(t, "5.3", req.Tags["cvss3_base_score"], "ACAS cvss3_base_score must be captured as a tag")
	require.NotEmpty(t, req.Cvss, "ACAS finding must carry a structured cvss[] entry")

	// IAVM (IAVA/IAVB) and stig_severity are preserved in the raw code blob.
	require.NotNil(t, req.Code)
	assert.Contains(t, *req.Code, `"stig_severity": "I"`, "ACAS stig_severity (STIG CAT) must be preserved")
	assert.Contains(t, *req.Code, "IAVA:2022-A-0031", "ACAS IAVM xref must be preserved")
}

func TestConvertNessusToHDF_Tool(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "sample.nessus")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertNessusToHDF(inputData, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Nessus", *result.Tool.Name)
	assert.Nil(t, result.Tool.Version)
	assert.Nil(t, result.Tool.Format)
}

func TestConvertNessusToHDF_Compliance(t *testing.T) {
	// Load compliance fixture
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "compliance.nessus")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read compliance.nessus fixture")

	// Convert
	result, err := ConvertNessusToHDF(inputData, converterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Verify basic structure
	assert.Len(t, result.Baselines, 1, "Should have 1 baseline")
	baseline := result.Baselines[0]
	assert.Equal(t, "Nessus DISA STIG Compliance Audit", baseline.Name)

	// Should have 5 compliance findings
	assert.Len(t, baseline.Requirements, 5, "Should have 5 compliance findings")

	// Test FAILED compliance result (CAT II)
	failedReq := shared.MustFindRequirement(t, baseline.Requirements, "V-71849")
	assert.Equal(t, "V-71849", failedReq.ID)
	assert.Contains(t, *failedReq.Title, "RHEL-07-010010")
	assert.Equal(t, 0.5, failedReq.Impact, "CAT II should map to 0.5")
	assert.Equal(t, hdf.Failed, failedReq.Results[0].Status)
	assert.Contains(t, failedReq.Tags, "stig_id")
	assert.Equal(t, "RHEL-07-010010", failedReq.Tags["stig_id"])

	// Test FAILED compliance result (CAT I - High)
	highReq := shared.MustFindRequirement(t, baseline.Requirements, "V-71971")
	assert.Equal(t, 0.7, highReq.Impact, "CAT I should map to 0.7")
	assert.Equal(t, hdf.Failed, highReq.Results[0].Status)

	// Test PASSED compliance result (CAT III - Low)
	passedReq := shared.MustFindRequirement(t, baseline.Requirements, "V-72083")
	assert.Equal(t, 0.3, passedReq.Impact, "CAT III should map to 0.3")
	assert.Equal(t, hdf.Passed, passedReq.Results[0].Status)

	// Test WARNING compliance result
	warningReq := shared.MustFindRequirement(t, baseline.Requirements, "V-72095")
	assert.Equal(t, hdf.NotApplicable, warningReq.Results[0].Status, "WARNING should map to notApplicable")

	// Test ERROR compliance result
	errorReq := shared.MustFindRequirement(t, baseline.Requirements, "V-72229")
	assert.Equal(t, hdf.Error, errorReq.Results[0].Status)

	// Write output for differential testing
	shared.WriteOutput(t, "nessus-to-hdf", "compliance.json", result)
}

func TestConvertNessusToHDF_ClassificationFields(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "compliance.nessus")
	input, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertNessusToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	// Nessus always serializes the item as code -> verificationMethod=automated
	// applies to every requirement. controlType is derived where NIST tags
	// resolve to a known family.
	var sawControlType, sawVerification bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawControlType = true
		}
		if req.VerificationMethod != nil {
			assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
				"every nessus requirement has non-empty code => automated")
			sawVerification = true
		}
	}
	assert.True(t, sawControlType, "at least one requirement should derive controlType")
	assert.True(t, sawVerification, "every requirement should have verificationMethod=automated")
}

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "nessus-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertNessusToHDF(input, converterVersion) },
		MinimalFixture: "compliance.nessus",
		InvalidInput:   "<not valid xml",
	})
}

func TestConvertNessusToHDF_EmptyHosts(t *testing.T) {
	emptyXML := []byte(`<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy>
    <policyName>Empty Scan</policyName>
    <Preferences>
      <ServerPreferences></ServerPreferences>
    </Preferences>
  </Policy>
  <Report name="Empty Scan"></Report>
</NessusClientData_v2>`)

	result, err := ConvertNessusToHDF(emptyXML, converterVersion)
	require.NoError(t, err, "Conversion should succeed with empty hosts")
	require.NotNil(t, result, "Result should not be nil")

	assert.Len(t, result.Baselines, 0, "Should have no baselines")
	assert.Len(t, result.Components, 0, "Should have no targets")
	assert.Equal(t, 0.0, *result.Statistics.Duration, "Duration should be 0")
}

func TestConvertNessusToHDF_EmptyHostSynthesizesPlaceholder(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "empty-host.nessus")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read empty-host.nessus fixture")

	result, err := ConvertNessusToHDF(inputData, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Len(t, result.Baselines, 1, "one ReportHost should produce one baseline")
	baseline := result.Baselines[0]
	require.Len(t, baseline.Requirements, 1, "empty host must synthesize one placeholder requirement")

	req := baseline.Requirements[0]
	assert.Equal(t, "nessus-no-findings", req.ID)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Nessus")
	assert.Contains(t, req.Results[0].CodeDesc, "scanned")
	assert.Contains(t, req.Results[0].CodeDesc, "cleanhost.example.com")
	assert.Contains(t, req.Results[0].CodeDesc, "findings")
}

func TestParseComplianceRef(t *testing.T) {
	ref := "CCI|CCI-000366,STIG-ID|RHEL-07-010010,Rule-ID|SV-86473r2_rule,Vuln-ID|V-71849,CAT|II"

	t.Run("Extract CCI", func(t *testing.T) {
		ccis := parseComplianceRef(ref, "CCI")
		assert.Len(t, ccis, 1)
		assert.Equal(t, "CCI-000366", ccis[0])
	})

	t.Run("Extract STIG-ID", func(t *testing.T) {
		stigIDs := parseComplianceRef(ref, "STIG-ID")
		assert.Len(t, stigIDs, 1)
		assert.Equal(t, "RHEL-07-010010", stigIDs[0])
	})

	t.Run("Extract Rule-ID", func(t *testing.T) {
		ruleIDs := parseComplianceRef(ref, "Rule-ID")
		assert.Len(t, ruleIDs, 1)
		assert.Equal(t, "SV-86473r2_rule", ruleIDs[0])
	})

	t.Run("Extract Vuln-ID", func(t *testing.T) {
		vulnIDs := parseComplianceRef(ref, "Vuln-ID")
		assert.Len(t, vulnIDs, 1)
		assert.Equal(t, "V-71849", vulnIDs[0])
	})

	t.Run("Extract CAT", func(t *testing.T) {
		cats := parseComplianceRef(ref, "CAT")
		assert.Len(t, cats, 1)
		assert.Equal(t, "II", cats[0])
	})

	t.Run("Missing key", func(t *testing.T) {
		results := parseComplianceRef(ref, "NONEXISTENT")
		assert.Len(t, results, 0)
	})
}

func TestParseHTML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple HTML",
			input:    "<p>This is a test</p>",
			expected: "This is a test",
		},
		{
			name:     "Multiple tags",
			input:    "<div><p>Hello</p><p>World</p></div>",
			expected: "HelloWorld",
		},
		{
			name:     "Line breaks in plugin text survive",
			input:    "First line.\n\n  - second line",
			expected: "First line.\n\n  - second line",
		},
		{
			name:     "No HTML",
			input:    "Plain text",
			expected: "Plain text",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "With whitespace",
			input:    "  <p>Text</p>  ",
			expected: "Text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHTML(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestImpactMapping(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"4", 0.9},   // Critical
		{"3", 0.7},   // High
		{"i", 0.7},   // High (compliance)
		{"2", 0.5},   // Medium
		{"ii", 0.5},  // Medium (compliance)
		{"1", 0.3},   // Low
		{"iii", 0.3}, // Low (compliance)
		{"0", 0.0},   // Info
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			impact, ok := nessusAliases[tt.severity]
			assert.True(t, ok, "Severity should be in mapping")
			assert.Equal(t, tt.expected, impact)
		})
	}
}

func TestParseHostTime(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		shouldOK bool
	}{
		{
			name:     "Nessus format",
			input:    "Mon Jan 29 10:00:00 2024",
			shouldOK: true,
		},
		{
			name:     "Empty string",
			input:    "",
			shouldOK: false, // Will return time.Now()
		},
		{
			name:     "RFC1123",
			input:    "Mon, 29 Jan 2024 10:00:00 GMT",
			shouldOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHostTime(tt.input)
			assert.NotNil(t, result)
			// Just verify it returns a valid time
			assert.False(t, result.IsZero())
		})
	}
}

func TestIsFQDN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"FQDN with subdomain", "rhel7-server.example.com", true},
		{"FQDN simple", "web01.prod.example.com", true},
		{"Two-part FQDN", "host.domain", true},
		{"IP address", "192.168.1.100", false},
		{"Simple hostname", "webserver", false},
		{"Localhost", "localhost", false},
		{"Hostname with hyphen", "web-server.example.com", true},
		{"Invalid - starts with hyphen", "-invalid.example.com", false},
		{"Invalid - ends with hyphen", "invalid-.example.com", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isFQDN(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// The short hostname HostProperty must be carried into the dedicated hostname
// field alongside the FQDN, not dropped.
func TestConvertReportHostToTarget_HostnameAndFQDN(t *testing.T) {
	host := &ReportHost{
		Name: "10.0.0.3",
		HostProperties: HostProperties{Tags: []HostPropertyTag{
			{Name: "hostname", Value: "web01"},
			{Name: "host-fqdn", Value: "web01.prod.example.com"},
			{Name: "host-ip", Value: "10.0.0.3"},
			{Name: "operating-system", Value: "Linux Kernel 5.13.0 on Ubuntu 20.04"},
		}},
	}
	c := convertReportHostToTarget(host)
	assert.Equal(t, hdf.Host, c.Type, "scan target is a host component")
	assert.Equal(t, "10.0.0.3", c.Name)
	require.NotNil(t, c.Hostname)
	assert.Equal(t, "web01", *c.Hostname)
	require.NotNil(t, c.FQDN)
	assert.Equal(t, "web01.prod.example.com", *c.FQDN)
	require.NotNil(t, c.IPAddress)
	assert.Equal(t, "10.0.0.3", *c.IPAddress)
	require.NotNil(t, c.OSName)
	assert.Equal(t, "Linux Kernel 5.13.0 on Ubuntu 20.04", *c.OSName, "operating-system carried verbatim into OSName")
}

// A host whose name is neither an IP nor an FQDN and that carries no
// HostProperties tags yields a host component with only Name+Type set; every
// optional identity field stays nil (the absent branch).
func TestConvertReportHostToTarget_AbsentProperties(t *testing.T) {
	host := &ReportHost{Name: "bare-target"}
	c := convertReportHostToTarget(host)
	assert.Equal(t, hdf.Host, c.Type)
	assert.Equal(t, "bare-target", c.Name)
	assert.Nil(t, c.Hostname)
	assert.Nil(t, c.FQDN)
	assert.Nil(t, c.IPAddress)
	assert.Nil(t, c.OSName)
	assert.Nil(t, c.OSVersion)
	assert.Nil(t, c.MACAddress)
}

// Real-fixture regression: the short hostname must survive end-to-end (it was
// silently dropped before the host-identity fields existed).
func TestConvertNessusToHDF_PreservesShortHostname(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "sample.nessus")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err)
	result, err := ConvertNessusToHDF(inputData, converterVersion)
	require.NoError(t, err)

	var host *hdf.Component
	for i := range result.Components {
		if result.Components[i].Name == "10.0.0.3" {
			host = &result.Components[i]
		}
	}
	require.NotNil(t, host, "host 10.0.0.3 not found")
	require.NotNil(t, host.Hostname, "short hostname should be preserved")
	assert.Equal(t, "s", *host.Hostname)
	require.NotNil(t, host.FQDN)
	assert.Equal(t, "DESKTOP-TEST001.localdomain", *host.FQDN)
}

func TestConvertNessusToHDF_SeeAlsoMultiURLSplit(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "sample.nessus")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertNessusToHDF(inputData, converterVersion)
	require.NoError(t, err)

	// Plugin 51192's see_also is:
	//   "https://www.itu.int/rec/T-REC-X.509/en\nhttps://en.wikipedia.org/wiki/X.509"
	// Each URL must become its own Reference entry with no embedded whitespace.
	// 51192 lives in whichever baseline carries it, so search across all of them
	// (a not-found-in-a-given-baseline is expected here, unlike MustFindRequirement).
	var req *hdf.EvaluatedRequirement
	for i := range result.Baselines {
		for j := range result.Baselines[i].Requirements {
			if result.Baselines[i].Requirements[j].ID == "51192" {
				req = &result.Baselines[i].Requirements[j]
				break
			}
		}
		if req != nil {
			break
		}
	}
	require.NotNil(t, req, "plugin 51192 not found")
	require.Len(t, req.Refs, 2, "see_also with two URLs should produce two refs")

	urls := map[string]bool{}
	for _, ref := range req.Refs {
		require.NotNil(t, ref.URL)
		assert.NotContains(t, *ref.URL, "\n", "ref.url must not contain newlines")
		assert.NotContains(t, *ref.URL, " ", "ref.url must not contain spaces")
		urls[*ref.URL] = true
	}
	assert.True(t, urls["https://www.itu.int/rec/T-REC-X.509/en"], "expected ITU X.509 url")
	assert.True(t, urls["https://en.wikipedia.org/wiki/X.509"], "expected Wikipedia X.509 url")
}

func TestConvertNessusToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertNessusToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "nessus-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertNessusToHDF(input, converterVersion)
	})
}

// TestConvertNessusToHDF_CvssV3WithTemporal verifies that a finding carrying
// both CVSS v2 and v3 vectors (with a temporal vector) emits a single Cvss
// entry on the version derived from the v3 vector prefix, with the temporal
// metric segment stripped of its "CVSS:3.x/" prefix. Plugin 156888 in
// sample.nessus has score-source CVE-2022-21291 and full v3 + temporal data.
func TestConvertNessusToHDF_CvssV3WithTemporal(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "sample.nessus")
	input, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertNessusToHDF(input, converterVersion)
	require.NoError(t, err)

	req := findReqAcrossBaselines(result, "156888")
	require.NotNil(t, req, "plugin 156888 should be present in some host baseline")

	require.Len(t, req.Cvss, 1, "CVE finding should emit exactly one Cvss entry")
	c := req.Cvss[0]
	assert.Equal(t, hdf.The30, c.Version, "v3 prefix CVSS:3.0 => version 3.0")
	require.NotNil(t, c.Source)
	assert.Equal(t, "CVE-2022-21291", *c.Source)
	require.NotNil(t, c.BaseVector)
	assert.Equal(t, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", *c.BaseVector)
	require.NotNil(t, c.BaseScore)
	assert.InDelta(t, 5.3, *c.BaseScore, 0.001)
	require.NotNil(t, c.BaseSeverity)
	assert.Equal(t, hdf.CVSSSeverityMedium, *c.BaseSeverity)
	require.NotNil(t, c.ThreatVector, "v3 temporal_vector should populate threatVector")
	assert.Equal(t, "E:U/RL:O/RC:C", *c.ThreatVector, "CVSS:3.0/ prefix must be stripped")
	require.NotNil(t, c.ThreatScore)
	assert.InDelta(t, 4.6, *c.ThreatScore, 0.001)
	require.NotNil(t, c.ComputedScore, "v3 temporal_score is the computed (post-threat) score")
	assert.InDelta(t, 4.6, *c.ComputedScore, 0.001)
	require.NotNil(t, c.ComputedSeverity)
	assert.Equal(t, hdf.CVSSSeverityMedium, *c.ComputedSeverity)

	// Legacy back-compat tags preserved for one release.
	assert.Equal(t, "5.3", req.Tags["cvss3_base_score"])
	assert.Equal(t, "5.0", req.Tags["cvss_base_score"])
}

// TestConvertNessusToHDF_CweCveAttribution verifies that a finding emitting
// a <cwe> element populates the structured cwe[] field in "CWE-N" format,
// and the cvss[] entry's source is the cvss_score_source CVE.
// Plugin 10114 (ICMP Timestamp) in sample.nessus has CWE-200 + CVE-1999-0524.
func TestConvertNessusToHDF_CweCveAttribution(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "sample.nessus")
	input, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertNessusToHDF(input, converterVersion)
	require.NoError(t, err)

	req := findReqAcrossBaselines(result, "10114")
	require.NotNil(t, req, "plugin 10114 should be present")
	assert.Equal(t, []string{"CWE-200"}, req.Cwe, "<cwe>200</cwe> should yield CWE-200")

	require.Len(t, req.Cvss, 1)
	c := req.Cvss[0]
	require.NotNil(t, c.Source)
	assert.Equal(t, "CVE-1999-0524", *c.Source)
	assert.Equal(t, hdf.The30, c.Version)
	require.NotNil(t, c.BaseVector)
	assert.Equal(t, "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", *c.BaseVector)
	require.NotNil(t, c.BaseScore)
	assert.InDelta(t, 0.0, *c.BaseScore, 0.001)
	// 0.0 score → "none" severity band per FIRST CVSS v3.
	require.NotNil(t, c.BaseSeverity)
	assert.Equal(t, hdf.None, *c.BaseSeverity)
	// No temporal data on this finding → no threat fields.
	assert.Nil(t, c.ThreatVector)
	assert.Nil(t, c.ThreatScore)
	assert.Nil(t, c.ComputedScore)
}

// TestConvertNessusToHDF_NonCveSkipsCvss verifies that a finding with no
// CVE-shaped cvss_score_source (e.g. plugin 57582 SSL Self-Signed Cert,
// which has v2 vector + base score but no CVE source) does NOT emit a Cvss
// entry — the structured cvss[] field is reserved for CVE findings.
func TestConvertNessusToHDF_NonCveSkipsCvss(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "sample.nessus")
	input, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertNessusToHDF(input, converterVersion)
	require.NoError(t, err)

	req := findReqAcrossBaselines(result, "57582")
	require.NotNil(t, req, "plugin 57582 should be present")
	assert.Empty(t, req.Cvss, "non-CVE finding should not emit Cvss entries")
	assert.Empty(t, req.Cwe, "no <cwe> element => empty cwe[]")
	// Legacy tag still present.
	assert.Equal(t, "6.4", req.Tags["cvss_base_score"])
}

func TestBuildCvssEntries_V2OnlyWithCVE(t *testing.T) {
	item := &ReportItem{
		CVSSScoreSource:    "CVE-2020-12345",
		CVSSVector:         "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N",
		CVSSBaseScore:      "6.4",
		CVSSTemporalVector: "CVSS2#E:U/RL:OF/RC:C",
		CVSSTemporalScore:  "5.1",
	}
	entries := buildCvssEntries(item)
	require.Len(t, entries, 1)
	c := entries[0]
	assert.Equal(t, hdf.The20, c.Version)
	// CVSS2# prefix must be stripped.
	require.NotNil(t, c.BaseVector)
	assert.Equal(t, "AV:N/AC:L/Au:N/C:P/I:P/A:N", *c.BaseVector)
	require.NotNil(t, c.BaseScore)
	assert.InDelta(t, 6.4, *c.BaseScore, 0.001)
	require.NotNil(t, c.ThreatVector)
	assert.Equal(t, "E:U/RL:OF/RC:C", *c.ThreatVector)
	require.NotNil(t, c.ThreatScore)
	assert.InDelta(t, 5.1, *c.ThreatScore, 0.001)
	require.NotNil(t, c.ComputedScore)
	assert.InDelta(t, 5.1, *c.ComputedScore, 0.001)
}

func TestBuildCvssEntries_NoCVEScoreSource(t *testing.T) {
	// Non-CVE score source ("Tenable" or empty) should return nil.
	assert.Nil(t, buildCvssEntries(&ReportItem{CVSSScoreSource: "Tenable", CVSSBaseScore: "5.0"}))
	assert.Nil(t, buildCvssEntries(&ReportItem{CVSSScoreSource: "", CVSSBaseScore: "5.0"}))
	// CVE source but no vector/score data → nil.
	assert.Nil(t, buildCvssEntries(&ReportItem{CVSSScoreSource: "CVE-2020-1"}))
}

func TestDetectV3Version(t *testing.T) {
	assert.Equal(t, hdf.The31, detectV3Version("CVSS:3.1/AV:N"))
	assert.Equal(t, hdf.The30, detectV3Version("CVSS:3.0/AV:N"))
	// No prefix → default 3.0.
	assert.Equal(t, hdf.The30, detectV3Version("AV:N/AC:L"))
	assert.Equal(t, hdf.The30, detectV3Version(""))
}

func TestStripVersionPrefix(t *testing.T) {
	assert.Equal(t, "E:U/RL:O", stripVersionPrefix("CVSS:3.0/E:U/RL:O"))
	assert.Equal(t, "E:U/RL:O", stripVersionPrefix("CVSS:3.1/E:U/RL:O"))
	assert.Equal(t, "E:A", stripVersionPrefix("CVSS:4.0/E:A"))
	// No prefix → unchanged.
	assert.Equal(t, "E:U/RL:O", stripVersionPrefix("E:U/RL:O"))
	assert.Equal(t, "", stripVersionPrefix(""))
}

func TestStripV2Prefix(t *testing.T) {
	assert.Equal(t, "AV:N/AC:L", stripV2Prefix("CVSS2#AV:N/AC:L"))
	assert.Equal(t, "AV:N/AC:L", stripV2Prefix("AV:N/AC:L"))
	assert.Equal(t, "", stripV2Prefix(""))
}

func TestParseFloatHelpers(t *testing.T) {
	assert.Nil(t, parseFloatPtr(""))
	assert.Nil(t, parseFloatPtr("garbage"))
	p := parseFloatPtr("4.6")
	require.NotNil(t, p)
	assert.InDelta(t, 4.6, *p, 0.001)
}

func TestCvssSeverityMapping(t *testing.T) {
	tests := []struct {
		score float64
		want  hdf.CVSSSeverity
	}{
		{0.0, hdf.None},
		{2.0, hdf.CVSSSeverityLow},
		{5.5, hdf.CVSSSeverityMedium},
		{8.0, hdf.CVSSSeverityHigh},
		{9.5, hdf.CVSSSeverityCritical},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, shared.CvssSeverityFromScore(tt.score))
	}
}

func TestBuildCweIDs(t *testing.T) {
	// Bare numeric (Nessus' typical form).
	assert.Equal(t, []string{"CWE-200"}, buildCweIDs(&ReportItem{CWE: []string{"200"}}))
	// Multiple, deduplicated + sorted.
	assert.Equal(t, []string{"CWE-200", "CWE-89"}, buildCweIDs(&ReportItem{CWE: []string{"200", "89", "200"}}))
	// Prefixed form.
	assert.Equal(t, []string{"CWE-79"}, buildCweIDs(&ReportItem{CWE: []string{"CWE-79"}}))
	// Empty.
	assert.Nil(t, buildCweIDs(&ReportItem{CWE: nil}))
	assert.Nil(t, buildCweIDs(&ReportItem{CWE: []string{""}}))
}

func TestBuildEpss(t *testing.T) {
	host := &ReportHost{HostProperties: HostProperties{Tags: []HostPropertyTag{
		{Name: "HOST_START", Value: "Mon Jan 29 10:00:00 2024"},
	}}}
	// No EPSS data → nil.
	assert.Nil(t, buildEpss(&ReportItem{}, host))
	// Score only.
	e := buildEpss(&ReportItem{EPSSScore: "0.75"}, host)
	require.NotNil(t, e)
	assert.InDelta(t, 0.75, e.Score, 0.001)
	assert.Equal(t, 0.0, e.Percentile)
	assert.Equal(t, "2024-01-29", e.Date)
	// Both fields.
	e = buildEpss(&ReportItem{EPSSScore: "0.5", EPSSPercentile: "0.9"}, host)
	require.NotNil(t, e)
	assert.InDelta(t, 0.5, e.Score, 0.001)
	assert.InDelta(t, 0.9, e.Percentile, 0.001)
}

func TestEpssDate_FallsBackToToday(t *testing.T) {
	host := &ReportHost{}
	got := epssDate(host)
	// Should be a YYYY-MM-DD shape (10 chars).
	assert.Len(t, got, 10)
	assert.Equal(t, "-", got[4:5])
	assert.Equal(t, "-", got[7:8])
}

// TestConvertNessusToHDF_Synopsis verifies the Nessus <synopsis> short summary
// is carried through as a descriptions[] entry labelled "synopsis" for both
// vulnerability and compliance findings, and is omitted when the source has
// no synopsis element.
func TestConvertNessusToHDF_Synopsis(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "sample.nessus")
	input, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertNessusToHDF(input, converterVersion)
	require.NoError(t, err)

	// Plugin 10114 (ICMP Timestamp) has a synopsis in the source.
	req := findReqAcrossBaselines(result, "10114")
	require.NotNil(t, req, "plugin 10114 should be present")
	syn := findDescription(req.Descriptions, "synopsis")
	require.NotNil(t, syn, "vulnerability finding should carry a synopsis description")
	assert.Equal(t, "It is possible to determine the exact time set on the remote host.", syn.Data)
}

func TestConvertNessusToHDF_SynopsisCompliance(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "compliance.nessus")
	input, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertNessusToHDF(input, converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "V-71849")
	syn := findDescription(req.Descriptions, "synopsis")
	require.NotNil(t, syn, "compliance finding should carry a synopsis description")
	assert.Equal(t, "The remote Red Hat Enterprise Linux host does not comply with DISA STIG requirements.", syn.Data)
}

// TestBuildDescriptions_SynopsisAbsent covers the branch where the source item
// carries no synopsis element: no "synopsis" description is emitted.
func TestBuildDescriptions_SynopsisAbsent(t *testing.T) {
	descs := buildDescriptions(&ReportItem{PluginFamily: "General", Port: "0", Protocol: "tcp"}, false)
	assert.Nil(t, findDescription(descs, "synopsis"), "no synopsis element => no synopsis description")

	// Present-branch parity at the unit level, including HTML stripping.
	descs = buildDescriptions(&ReportItem{Synopsis: "<b>Summary</b> text."}, false)
	syn := findDescription(descs, "synopsis")
	require.NotNil(t, syn)
	assert.Equal(t, "Summary text.", syn.Data)
}

// findDescription returns the first description with the given label, or nil.
func findDescription(descs []hdf.Description, label string) *hdf.Description {
	for i := range descs {
		if descs[i].Label == label {
			return &descs[i]
		}
	}
	return nil
}

// findReqAcrossBaselines searches all baselines for a requirement by ID.
func findReqAcrossBaselines(result *hdf.HDFResults, id string) *hdf.EvaluatedRequirement {
	for bi := range result.Baselines {
		for ri := range result.Baselines[bi].Requirements {
			if result.Baselines[bi].Requirements[ri].ID == id {
				return &result.Baselines[bi].Requirements[ri]
			}
		}
	}
	return nil
}
