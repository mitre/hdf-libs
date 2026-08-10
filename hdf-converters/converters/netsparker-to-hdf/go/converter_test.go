package netsparker

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "test-0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

func findDescription(descs []hdf.Description, label string) *hdf.Description {
	for i := range descs {
		if descs[i].Label == label {
			return &descs[i]
		}
	}
	return nil
}

// ---- Input validation ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "netsparker-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertNetsparkerToHDF(input, testVersion) },
		MinimalFixture: "sample-netsparker-invicti.xml",
		InvalidInput:   "<not valid xml",
	})
}

// ---- Baseline structure ----

func TestConvertNetsparker_BaselineCount(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
}

func TestConvertNetsparker_RequirementCount(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	// Fixture has 3 unique vulnerabilities
	assert.Len(t, result.Baselines[0].Requirements, 3)
}

func TestConvertNetsparker_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "Netsparker Scan", result.Baselines[0].Name)
}

func TestConvertNetsparker_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	// Title should contain scan ID and URL
	assert.Contains(t, *result.Baselines[0].Title, "1eb9f18bfec849d2e438afb704b6a011")
	assert.Contains(t, *result.Baselines[0].Title, "https://foo.bar/")
}

func TestConvertNetsparker_Checksum(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Generator ----

func TestConvertNetsparker_Generator(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "netsparker-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvertNetsparker_Tool(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Contains(t, *result.Tool.Name, "Invicti")
	assert.Nil(t, result.Tool.Format, "serialization structures are not formats (kpvj)")
}

// ---- Target ----

func TestConvertNetsparker_Target(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	assert.Equal(t, "https://foo.bar/", result.Components[0].Name)
	assert.Equal(t, hdf.Application, result.Components[0].Type)
}

// ---- Requirement IDs use LookupId ----

func TestConvertNetsparker_RequirementID(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
}

// ---- Requirement title ----

func TestConvertNetsparker_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	require.NotNil(t, req.Title)
	assert.Equal(t, "Weak Ciphers Enabled", *req.Title)
}

// ---- Severity → Impact ----

func TestConvertNetsparker_Severity(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// Medium → 0.5
	medium := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	assert.InDelta(t, 0.5, medium.Impact, 0.001)

	// Low → 0.3
	low := shared.MustFindRequirement(t, reqs, "8d8e6052-221d-41c4-8f1e-af9704473901")
	assert.InDelta(t, 0.3, low.Impact, 0.001)
}

func TestSeverityToImpact(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"critical", 0.9},
		{"Critical", 0.9},
		{"high", 0.7},
		{"High", 0.7},
		{"medium", 0.5},
		{"Medium", 0.5},
		{"low", 0.3},
		{"Low", 0.3},
		{"best_practice", 0.0},
		{"information", 0.0},
		{"", 0.5},
		{"unknown", 0.5},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.InDelta(t, tc.expected, getImpact(tc.severity), 0.001)
		})
	}
}

// ---- Dual NIST mapping: CWE + OWASP ----

func TestConvertNetsparker_DualNistMapping(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// First vuln: CWE-327 → SC-12/SC-13, OWASP A6 → CM-6
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist, "nist tag should be present")
	assert.NotEmpty(t, nist)
	// Should contain OWASP A6 mapping (CM-6) in addition to CWE mappings
	assert.Contains(t, nist, "CM-6", "should contain OWASP A6 -> CM-6 mapping")
}

// ---- Tags ----

func TestConvertNetsparker_Tags(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")

	// nist should be present
	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist)
	assert.NotEmpty(t, nist)

	// cci should be present
	cciSlice := hdfutil.SafeStringSlice(req.Tags["cci"])
	require.NotNil(t, cciSlice)
	assert.NotEmpty(t, cciSlice)

	// cweid should be present
	_, ok := req.Tags["cweid"]
	assert.True(t, ok, "cweid tag should be present")

	// owasp should be present
	_, ok = req.Tags["owasp"]
	assert.True(t, ok, "owasp tag should be present")
}

// ---- Classification tags (capec / wasc / iso27001 / pci32) ----

func TestConvertNetsparker_ClassificationTags(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// Vuln 1: capec=217, wasc=4, iso27001=A.14.1.3, pci32=6.5.4 (all present).
	v1 := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	assert.Equal(t, "217", v1.Tags["capec"])
	assert.Equal(t, "4", v1.Tags["wasc"])
	assert.Equal(t, "A.14.1.3", v1.Tags["iso27001"])
	assert.Equal(t, "6.5.4", v1.Tags["pci32"])
	// hipaa and owasppc are empty in every fixture vuln → never tagged.
	_, hasHipaa := v1.Tags["hipaa"]
	assert.False(t, hasHipaa, "hipaa is empty in source → tag omitted")
	_, hasOwasppc := v1.Tags["owasppc"]
	assert.False(t, hasOwasppc, "owasppc is empty in source → tag omitted")

	// Vuln 2: wasc=15, iso27001=A.14.1.2; capec and pci32 empty → omitted.
	v2 := shared.MustFindRequirement(t, reqs, "9c3a51bf-6c1f-47c9-4646-afb704bb8fb0")
	assert.Equal(t, "15", v2.Tags["wasc"])
	assert.Equal(t, "A.14.1.2", v2.Tags["iso27001"])
	_, hasCapec := v2.Tags["capec"]
	assert.False(t, hasCapec, "empty capec → tag omitted")
	_, hasPci := v2.Tags["pci32"]
	assert.False(t, hasPci, "empty pci32 → tag omitted")

	// Vuln 3: capec=103, iso27001=A.14.2.5; wasc empty → omitted.
	v3 := shared.MustFindRequirement(t, reqs, "8d8e6052-221d-41c4-8f1e-af9704473901")
	assert.Equal(t, "103", v3.Tags["capec"])
	assert.Equal(t, "A.14.2.5", v3.Tags["iso27001"])
	_, hasWasc := v3.Tags["wasc"]
	assert.False(t, hasWasc, "empty wasc → tag omitted")
}

// ---- Descriptions ----

func TestConvertNetsparker_Descriptions(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")

	// Should have at least a default description
	desc := findDescription(req.Descriptions, "default")
	require.NotNil(t, desc, "expected a 'default' description")
	assert.NotEmpty(t, desc.Data)

	// Check description (from exploitation-skills/proof-of-concept)
	check := findDescription(req.Descriptions, "check")
	// check may be nil if exploitation-skills is empty (which it is for this vuln),
	// so we just ensure default exists

	// Fix description (from remedial-actions/remedial-procedure)
	fix := findDescription(req.Descriptions, "fix")
	require.NotNil(t, fix, "expected a 'fix' description")
	assert.NotEmpty(t, fix.Data)
	_ = check
}

// ---- External references → refs[] ----

func TestConvertNetsparker_Refs(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")

	// First vuln's <external-references> carries five anchor links.
	require.Len(t, req.Refs, 5)
	require.NotNil(t, req.Refs[0].URL)
	assert.Equal(t, "https://wiki.owasp.org/index.php/Insecure_Configuration_Management", *req.Refs[0].URL)
	require.NotNil(t, req.Refs[4].URL)
	assert.Equal(t, "https://syslink.pl/cipherlist/", *req.Refs[4].URL)
}

func TestConvertNetsparker_RefsAbsent(t *testing.T) {
	// Crafted vuln with no <external-references> element → refs must stay unset.
	xml := `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
	<target>
		<url>https://example.com/</url>
	</target>
	<vulnerabilities>
		<vulnerability>
			<LookupId>no-refs</LookupId>
			<name>No Refs Vuln</name>
			<severity>Low</severity>
		</vulnerability>
	</vulnerabilities>
</netsparker-enterprise>`

	result, err := ConvertNetsparkerToHDF([]byte(xml), testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "no-refs")
	assert.Empty(t, req.Refs, "refs should be unset when the vuln carries no external-references")
}

func TestBuildRefs(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		assert.Nil(t, buildRefs(""))
	})
	t.Run("no anchors", func(t *testing.T) {
		assert.Nil(t, buildRefs("<div>plain text, no links</div>"))
	})
	t.Run("double-quoted href", func(t *testing.T) {
		refs := buildRefs(`<a href="https://example.com/x">x</a>`)
		require.Len(t, refs, 1)
		require.NotNil(t, refs[0].URL)
		assert.Equal(t, "https://example.com/x", *refs[0].URL)
	})
	t.Run("skips non-absolute hrefs", func(t *testing.T) {
		refs := buildRefs(`<a href="https://example.com/x">abs</a><a href="/relative/path">rel</a><a href="#frag">frag</a><a href="   ">blank</a>`)
		require.Len(t, refs, 1)
		require.NotNil(t, refs[0].URL)
		assert.Equal(t, "https://example.com/x", *refs[0].URL)
	})
	t.Run("nil when only non-absolute hrefs", func(t *testing.T) {
		assert.Nil(t, buildRefs(`<a href="/relative">rel</a><a href="#frag">f</a>`))
	})
}

// ---- Status: all results Failed ----

func TestConvertNetsparker_AllResultsFailed(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, r := range req.Results {
			assert.Equal(t, hdf.Failed, r.Status,
				"all Netsparker vulnerabilities should be Failed (vuln %s)", req.ID)
		}
	}
}

// ---- CodeDesc contains HTTP request info ----

func TestConvertNetsparker_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	require.NotEmpty(t, req.Results)

	codeDesc := req.Results[0].CodeDesc
	assert.Contains(t, codeDesc, "http-request")
	assert.Contains(t, codeDesc, "GET")
}

// ---- requirement.code holds the raw HTTP request (CODE tab) ----

func TestConvertNetsparker_Code(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// First vuln: http-request content is "[SSL Connection]"
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	require.NotNil(t, req.Code, "requirement.code should carry the raw HTTP request")
	assert.Equal(t, "[SSL Connection]", *req.Code)

	// Second vuln: full raw GET request preserved verbatim
	req2 := shared.MustFindRequirement(t, reqs, "9c3a51bf-6c1f-47c9-4646-afb704bb8fb0")
	require.NotNil(t, req2.Code)
	assert.Contains(t, *req2.Code, "GET / HTTP/1.1")
	assert.Contains(t, *req2.Code, "Host: mlrcommercial.vams-impl.cms.gov")
	// code is the RAW request only — no "method :" / "http-request :" framing
	assert.NotContains(t, *req2.Code, "method :")
}

func TestConvertNetsparker_CodeUnsetWhenNoHTTPRequest(t *testing.T) {
	// Crafted vuln with no <http-request> element → code must stay unset.
	xml := `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
	<target>
		<url>https://example.com/</url>
	</target>
	<vulnerabilities>
		<vulnerability>
			<LookupId>no-http-request</LookupId>
			<name>No Request Vuln</name>
			<severity>Low</severity>
		</vulnerability>
	</vulnerabilities>
</netsparker-enterprise>`

	result, err := ConvertNetsparkerToHDF([]byte(xml), testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "no-http-request")
	assert.Nil(t, req.Code, "code should be unset when the vuln carries no http-request content")
}

// ---- Message contains HTTP response info ----

func TestConvertNetsparker_Message(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	require.NotEmpty(t, req.Results)
	require.NotNil(t, req.Results[0].Message)
	assert.Contains(t, *req.Results[0].Message, "http-response")
}

// ---- StartTime from target initiated ----

func TestConvertNetsparker_StartTime(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	require.NotEmpty(t, req.Results)

	// StartTime should be non-zero (parsed from target initiated)
	assert.False(t, req.Results[0].StartTime.IsZero(), "startTime should not be zero")
}

// ---- Top-level timestamp from `generated` attribute ----

func TestConvertNetsparker_Timestamp(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	// Fixture carries `generated="03/07/2023 03:15 PM"`; parsed as UTC that is
	// 2023-03-07T15:15:00Z. The shared snapshot masks the top-level timestamp,
	// so pin the exact source-derived value here.
	require.NotNil(t, result.Timestamp)
	assert.Equal(t, "2023-03-07T15:15:00Z", result.Timestamp.UTC().Format(time.RFC3339))
}

func TestConvertNetsparker_TimestampFallback(t *testing.T) {
	// No `generated` attribute → the converter falls back to a valid, non-zero
	// timestamp rather than omitting or emitting a zero value.
	xml := `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise>
	<target>
		<url>https://example.com/</url>
	</target>
	<vulnerabilities>
		<vulnerability>
			<LookupId>no-generated</LookupId>
			<name>No Generated Vuln</name>
			<severity>Low</severity>
		</vulnerability>
	</vulnerabilities>
</netsparker-enterprise>`

	result, err := ConvertNetsparkerToHDF([]byte(xml), testVersion)
	require.NoError(t, err)
	require.NotNil(t, result.Timestamp, "timestamp must fall back to a valid value when generated is absent")
	assert.False(t, result.Timestamp.IsZero(), "fallback timestamp must be non-zero")
}

// ---- Netsparker root element detection ----

func TestConvertNetsparker_NetsparkerRootElement(t *testing.T) {
	// Test with netsparker-enterprise root element
	netsparkerXML := `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise generated="03/07/2023 03:15 PM">
	<target>
		<scan-id>abc123</scan-id>
		<url>https://example.com/</url>
		<initiated>05/05/2023 04:57 PM</initiated>
	</target>
	<vulnerabilities>
		<vulnerability>
			<LookupId>test-id-1</LookupId>
			<url>https://example.com/</url>
			<type>TestVuln</type>
			<name>Test Vulnerability</name>
			<severity>High</severity>
			<certainty>100</certainty>
			<confirmed>True</confirmed>
			<state>Present</state>
			<classification>
				<owasp>A1</owasp>
				<cwe>89</cwe>
			</classification>
			<http-request>
				<method>GET</method>
				<content>GET / HTTP/1.1</content>
			</http-request>
			<http-response>
				<status-code>200</status-code>
				<duration>1</duration>
				<content>HTTP/1.1 200 OK</content>
			</http-response>
			<description>SQL Injection</description>
			<impact>Data loss</impact>
			<remedial-actions>Use parameterized queries</remedial-actions>
			<remedial-procedure>Fix the code</remedial-procedure>
		</vulnerability>
	</vulnerabilities>
</netsparker-enterprise>`

	result, err := ConvertNetsparkerToHDF([]byte(netsparkerXML), testVersion)
	require.NoError(t, err)

	// Tool name should be "Netsparker" for netsparker-enterprise root
	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Netsparker", *result.Tool.Name)
}

func TestConvertNetsparkerToHDF_EmptyVulnerabilities(t *testing.T) {
	input := loadFixture(t, "input/empty.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "netsparker-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Invicti")
	assert.Contains(t, req.Results[0].CodeDesc, "https://clean.example.com/")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

func TestConvertNetsparkerToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertNetsparkerToHDF(input, testVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

// ---- Structured CVSS ----

func TestConvertNetsparker_Cvss(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// First vuln carries both <cvss> (3.0) and <cvss31> (3.1) blocks.
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	require.Len(t, req.Cvss, 2, "expected one cvss[] entry per CVSS block")

	// cvss (3.0) first.
	require.NotNil(t, req.Cvss[0].BaseScore)
	assert.InDelta(t, 6.8, *req.Cvss[0].BaseScore, 0.001)
	assert.Equal(t, hdf.The30, req.Cvss[0].Version)
	require.NotNil(t, req.Cvss[0].BaseVector)
	assert.Equal(t, "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", *req.Cvss[0].BaseVector)
	require.NotNil(t, req.Cvss[0].BaseSeverity)
	assert.Equal(t, hdf.CVSSSeverityMedium, *req.Cvss[0].BaseSeverity)

	// cvss31 (3.1) second.
	require.NotNil(t, req.Cvss[1].BaseScore)
	assert.InDelta(t, 6.8, *req.Cvss[1].BaseScore, 0.001)
	assert.Equal(t, hdf.The31, req.Cvss[1].Version)
	require.NotNil(t, req.Cvss[1].BaseVector)
	assert.Equal(t, "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", *req.Cvss[1].BaseVector)
}

func TestConvertNetsparker_CvssAbsent(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// Second and third vulns carry no CVSS blocks → cvss[] omitted.
	for _, id := range []string{"9c3a51bf-6c1f-47c9-4646-afb704bb8fb0", "8d8e6052-221d-41c4-8f1e-af9704473901"} {
		req := shared.MustFindRequirement(t, reqs, id)
		assert.Empty(t, req.Cvss, "cvss[] should be omitted when the vuln carries no CVSS block (%s)", id)
	}
}

func TestBaseScoreFromScores(t *testing.T) {
	t.Run("base present and parseable", func(t *testing.T) {
		got := baseScoreFromScores([]NetsparkerCVSSScore{
			{Type: "Temporal", Value: "5.0"},
			{Type: "Base", Value: " 6.8 "},
		})
		require.NotNil(t, got)
		assert.InDelta(t, 6.8, *got, 0.001)
	})
	t.Run("base present but unparseable", func(t *testing.T) {
		got := baseScoreFromScores([]NetsparkerCVSSScore{{Type: "Base", Value: "N/A"}})
		assert.Nil(t, got)
	})
	t.Run("no base score", func(t *testing.T) {
		got := baseScoreFromScores([]NetsparkerCVSSScore{{Type: "Temporal", Value: "6.8"}})
		assert.Nil(t, got)
	})
	t.Run("empty scores", func(t *testing.T) {
		assert.Nil(t, baseScoreFromScores(nil))
	})
}

func TestBuildNetsparkerCvss(t *testing.T) {
	t.Run("both blocks", func(t *testing.T) {
		out := buildNetsparkerCvss(NetsparkerClassification{
			CVSS:   NetsparkerCVSS{Vector: "CVSS:3.0/AV:N", Scores: []NetsparkerCVSSScore{{Type: "Base", Value: "6.8"}}},
			CVSS31: NetsparkerCVSS{Vector: "CVSS:3.1/AV:N", Scores: []NetsparkerCVSSScore{{Type: "Base", Value: "7.5"}}},
		})
		require.Len(t, out, 2)
		assert.Equal(t, hdf.The30, out[0].Version)
		assert.Equal(t, hdf.The31, out[1].Version)
	})
	t.Run("vector only, no score", func(t *testing.T) {
		out := buildNetsparkerCvss(NetsparkerClassification{
			CVSS: NetsparkerCVSS{Vector: "CVSS:3.1/AV:N"},
		})
		require.Len(t, out, 1)
		assert.Nil(t, out[0].BaseScore)
		require.NotNil(t, out[0].BaseVector)
	})
	t.Run("score only, no vector", func(t *testing.T) {
		out := buildNetsparkerCvss(NetsparkerClassification{
			CVSS31: NetsparkerCVSS{Scores: []NetsparkerCVSSScore{{Type: "Base", Value: "4.0"}}},
		})
		require.Len(t, out, 1)
		require.NotNil(t, out[0].BaseScore)
		assert.Nil(t, out[0].BaseVector)
	})
	t.Run("no blocks", func(t *testing.T) {
		assert.Empty(t, buildNetsparkerCvss(NetsparkerClassification{}))
	})
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "netsparker-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertNetsparkerToHDF(input, "1.0.0")
	})
}

func TestConvertNetsparker_ControlType(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	// Netsparker resolves NIST tags via CWE and OWASP mappings (falling back
	// to DefaultStaticAnalysisNIST). At least one requirement should derive
	// a controlType.
	var sawDerivation bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawDerivation = true
			switch *req.ControlType {
			case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
			default:
				t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
			}
		}
	}
	assert.True(t, sawDerivation, "at least one Netsparker requirement should have a derived controlType")
}

func TestConvertNetsparker_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)
	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q: Netsparker/Invicti is an automated DAST scanner", req.ID)
	}
}

// Ground-truth anchor (input-derived count; see shared/go/anchor.go). Golden
// parity proves Go and TS agree, not that either is correct. Netsparker emits
// one requirement per <vulnerability> element (no grouping/dedup); assert that
// count derived INDEPENDENTLY from the source XML, so a silent under-extraction
// fails even when both languages agree.
func TestConvertNetsparker_VulnerabilityAnchor(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	want := shared.CountXMLElements(t, input, "vulnerability")
	shared.AssertRequirementCount(t, result, want,
		"sample-netsparker-invicti.xml: one requirement per <vulnerability>")
}
