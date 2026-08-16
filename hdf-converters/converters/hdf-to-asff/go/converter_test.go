package hdftoasff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

func fixture(t *testing.T, kind, name string) []byte {
	t.Helper()
	p := filepath.Join(shared.GetConvertersDir(), "hdf-to-asff", "fixtures", kind, name)
	data, err := os.ReadFile(p)
	require.NoError(t, err, "read fixture %s", p)
	return data
}

// findings parses the {"Findings":[...]} envelope into a slice of objects.
func findings(t *testing.T, out []byte) []map[string]interface{} {
	t.Helper()
	var env struct {
		Findings []map[string]interface{} `json:"Findings"`
	}
	require.NoError(t, json.Unmarshal(out, &env), "output must be a Findings envelope")
	require.Equal(t, byte('\n'), out[len(out)-1], "output must end with a trailing newline")
	return env.Findings
}

func convert(t *testing.T, name string) []map[string]interface{} {
	t.Helper()
	out, err := ConvertHDFToASFF(fixture(t, "input", name), converterVersion)
	require.NoError(t, err)
	return findings(t, out)
}

func TestConvert_EmptyAndInvalid(t *testing.T) {
	_, err := ConvertHDFToASFF([]byte(""), converterVersion)
	assert.Error(t, err)
	_, err = ConvertHDFToASFF([]byte("not json"), converterVersion)
	assert.Error(t, err)
	_, err = ConvertHDFToASFF([]byte(`{"foo":1}`), converterVersion)
	assert.Error(t, err, "missing baselines must error")
}

func TestConvert_RequiredAttributes(t *testing.T) {
	for _, f := range convert(t, "compliance.json") {
		for _, k := range []string{"SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId", "CreatedAt", "UpdatedAt", "Title", "Description", "Types", "Severity", "Resources", "Compliance"} {
			assert.Contains(t, f, k, "required ASFF attribute %q", k)
		}
		assert.Equal(t, "2018-10-08", f["SchemaVersion"])
		res := f["Resources"].([]interface{})
		assert.NotEmpty(t, res, "ASFF requires at least one Resource")
	}
}

func TestConvert_TypesRouting(t *testing.T) {
	// CVE-bearing requirement -> Vulnerabilities/CVE type
	for _, f := range convert(t, "cve.json") {
		assert.Equal(t, []interface{}{"Software and Configuration Checks/Vulnerabilities/CVE"}, f["Types"])
	}
	// compliance requirement -> configuration-check type
	for _, f := range convert(t, "compliance.json") {
		assert.Equal(t, []interface{}{"Software and Configuration Checks"}, f["Types"])
	}
}

func TestConvert_ComplianceStatus(t *testing.T) {
	// compliance.json failing control -> FAILED
	f := convert(t, "compliance.json")[0]
	comp := f["Compliance"].(map[string]interface{})
	assert.Contains(t, []string{"PASSED", "FAILED", "WARNING", "NOT_AVAILABLE"}, comp["Status"])
}

func TestConvert_AccountRecoveredFromComponent(t *testing.T) {
	// cloudaccount.json carries a cloudAccount component; its id must surface as
	// AwsAccountId rather than the placeholder.
	f := convert(t, "cloudaccount.json")[0]
	assert.NotEqual(t, placeholderAccountID, f["AwsAccountId"])
	assert.Equal(t, "123456789123", f["AwsAccountId"])
}

func TestConvert_AccountPlaceholderWhenNoCloudAccount(t *testing.T) {
	// cve.json has only a host component -> placeholder account id.
	f := convert(t, "cve.json")[0]
	assert.Equal(t, placeholderAccountID, f["AwsAccountId"])
}

func TestComplianceStatus(t *testing.T) {
	assert.Equal(t, "PASSED", complianceStatus("passed"))
	assert.Equal(t, "FAILED", complianceStatus("failed"))
	assert.Equal(t, "NOT_AVAILABLE", complianceStatus("notApplicable"))
	assert.Equal(t, "WARNING", complianceStatus("notReviewed"))
	assert.Equal(t, "WARNING", complianceStatus("error"))
	assert.Equal(t, "WARNING", complianceStatus("bogus"))
}

func TestSeverity(t *testing.T) {
	mk := func(impact float64) map[string]interface{} { return map[string]interface{}{"impact": impact} }
	assert.Equal(t, "CRITICAL", severity(mk(0.9))["Label"])
	assert.Equal(t, "HIGH", severity(mk(0.7))["Label"])
	assert.Equal(t, "MEDIUM", severity(mk(0.5))["Label"])
	assert.Equal(t, "INFORMATIONAL", severity(mk(0.0))["Label"])
	assert.Equal(t, 50, severity(mk(0.5))["Normalized"])
}

func TestCanonicalTime(t *testing.T) {
	assert.Equal(t, "2022-03-22T14:54:47Z", canonicalTime("2022-03-22T14:54:47Z"))
	assert.Equal(t, epochSentinel, canonicalTime(""), "absent time falls back to epoch sentinel")
	assert.Equal(t, epochSentinel, canonicalTime("not-a-time"))
}

func TestConvert_Suppressed(t *testing.T) {
	doc := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"C-1","title":"t","results":[{"status":"failed","codeDesc":"c","startTime":"2024-01-01T00:00:00Z"}],"effectiveStatus":"passed","statusOverrides":[{"type":"waiver"}]}]}]}`)
	out, err := ConvertHDFToASFF(doc, converterVersion)
	require.NoError(t, err)
	f := findings(t, out)[0]
	assert.Equal(t, map[string]interface{}{"Status": "SUPPRESSED"}, f["Workflow"])
	assert.Equal(t, "PASSED", f["Compliance"].(map[string]interface{})["Status"])
}

func TestConvert_AccountIdField(t *testing.T) {
	doc := []byte(`{"components":[{"type":"cloudAccount","accountId":"999888777666"}],"baselines":[{"name":"b","requirements":[{"id":"C-1","results":[{"status":"passed","startTime":"2024-01-01T00:00:00Z"}]}]}]}`)
	out, err := ConvertHDFToASFF(doc, converterVersion)
	require.NoError(t, err)
	assert.Equal(t, "999888777666", findings(t, out)[0]["AwsAccountId"])
}

// findingByGenerator returns the finding whose GeneratorId matches, failing the
// test when absent.
func findingByGenerator(t *testing.T, fs []map[string]interface{}, gen string) map[string]interface{} {
	t.Helper()
	for _, f := range fs {
		if f["GeneratorId"] == gen {
			return f
		}
	}
	require.FailNowf(t, "no finding", "GeneratorId %q not found", gen)
	return nil
}

// TestConvert_Vulnerabilities pins requirement.cvss[] -> ASFF Vulnerabilities[]
// with the exact Id / Cvss[].{Version,BaseScore,Source,BaseVector} the reverse
// converter reads back into requirement.cvss[] and the CVE.
func TestConvert_Vulnerabilities(t *testing.T) {
	f := findingByGenerator(t, convert(t, "cve.json"), "156888")
	vulns := f["Vulnerabilities"].([]interface{})
	require.Len(t, vulns, 1)
	v := vulns[0].(map[string]interface{})
	assert.Equal(t, "CVE-2022-21291", v["Id"])
	cvss := v["Cvss"].([]interface{})
	require.Len(t, cvss, 1)
	c := cvss[0].(map[string]interface{})
	assert.Equal(t, "3.0", c["Version"])
	assert.Equal(t, 5.3, c["BaseScore"])
	assert.Equal(t, "CVE-2022-21291", c["Source"])
	assert.Equal(t, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", c["BaseVector"])
	// Both refs[].url ride the vuln's ReferenceUrls (the reverse rebuilds refs[]).
	assert.Equal(t, []interface{}{
		"https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml",
		"https://www.oracle.com/security-alerts/cpujan2022.html#AppendixJAVA",
	}, v["ReferenceUrls"])
}

// TestConvert_VulnerabilitiesZeroScore pins a base score of 0 (present, not
// omitted) and the absence of ReferenceUrls when a requirement carries no refs.
func TestConvert_VulnerabilitiesZeroScore(t *testing.T) {
	f := findingByGenerator(t, convert(t, "cve.json"), "10223")
	v := f["Vulnerabilities"].([]interface{})[0].(map[string]interface{})
	c := v["Cvss"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, 0.0, c["BaseScore"])
	assert.NotContains(t, v, "ReferenceUrls")
}

// TestConvert_RelatedRequirements pins tags.nist + tags.cci -> Compliance.RelatedRequirements.
func TestConvert_RelatedRequirements(t *testing.T) {
	f := findingByGenerator(t, convert(t, "compliance.json"), "SV-204393")
	comp := f["Compliance"].(map[string]interface{})
	assert.Equal(t, []interface{}{"AC-8 a", "AC-8.1 (ii)", "CCI-000048"}, comp["RelatedRequirements"])
}

// TestConvert_StatusReasons pins results[].message -> Compliance.StatusReasons[],
// the exact inverse of asff-to-hdf's statusReason flatten.
func TestConvert_StatusReasons(t *testing.T) {
	f := findingByGenerator(t, convert(t, "cloudaccount.json"), "1.1")
	sr := f["Compliance"].(map[string]interface{})["StatusReasons"].([]interface{})
	require.Len(t, sr, 1)
	assert.Equal(t, map[string]interface{}{
		"ReasonCode":  "CLOUDTRAIL_MULTI_REGION_NOT_PRESENT",
		"Description": "Multi region CloudTrail with the required configuration does not exist in the account",
	}, sr[0])
}

// TestConvert_FreeFormMessageIsNotStatusReasons pins that a non-ReasonCode
// message (the Nessus scan text) does not become StatusReasons.
func TestConvert_FreeFormMessageIsNotStatusReasons(t *testing.T) {
	f := findingByGenerator(t, convert(t, "cve.json"), "156888")
	assert.NotContains(t, f["Compliance"].(map[string]interface{}), "StatusReasons")
}

// TestConvert_ProductFieldsProvenance pins tool/generator/baseline-version onto ProductFields.
func TestConvert_ProductFieldsProvenance(t *testing.T) {
	pf := convert(t, "cve.json")[0]["ProductFields"].(map[string]interface{})
	assert.Equal(t, "Nessus", pf["hdf/tool"])
	assert.Equal(t, "nessus-to-hdf", pf["hdf/generator"])
	assert.Equal(t, "1.0.0", pf["hdf/baseline_version"])
	// A baseline without a version omits the key.
	cpf := convert(t, "cloudaccount.json")[0]["ProductFields"].(map[string]interface{})
	assert.NotContains(t, cpf, "hdf/baseline_version")
}

func TestConvert_GoldenParity(t *testing.T) {
	for _, name := range []string{"compliance", "cve", "cloudaccount"} {
		out, err := ConvertHDFToASFF(fixture(t, "input", name+".json"), converterVersion)
		require.NoError(t, err)
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			goldenPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-asff", "fixtures", "expected", name+".asff.json")
			require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
			continue
		}
		want := fixture(t, "expected", name+".asff.json")
		assert.Equal(t, string(want), string(out), "golden mismatch for %s", name)
	}
}
