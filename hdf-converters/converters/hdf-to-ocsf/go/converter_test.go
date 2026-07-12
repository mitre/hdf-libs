package hdftoocsf

import (
	"bytes"
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
	p := filepath.Join(shared.GetConvertersDir(), "hdf-to-ocsf", "fixtures", kind, name)
	data, err := os.ReadFile(p)
	require.NoError(t, err, "read fixture %s", p)
	return data
}

func parseLines(t *testing.T, out []byte) []map[string]interface{} {
	t.Helper()
	require.True(t, len(out) > 0, "output is empty")
	require.Equal(t, byte('\n'), out[len(out)-1], "output must end with a trailing newline")
	var objs []map[string]interface{}
	for _, line := range bytes.Split(bytes.TrimRight(out, "\n"), []byte("\n")) {
		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(line, &m), "each line must be standalone JSON: %s", line)
		objs = append(objs, m)
	}
	return objs
}

func sub(t *testing.T, m map[string]interface{}, key string) map[string]interface{} {
	t.Helper()
	v, ok := m[key].(map[string]interface{})
	require.True(t, ok, "expected object at key %q", key)
	return v
}

func TestConvert_EmptyAndInvalid(t *testing.T) {
	_, err := ConvertHDFToOCSF([]byte(""), converterVersion)
	assert.Error(t, err)
	_, err = ConvertHDFToOCSF([]byte("not json"), converterVersion)
	assert.Error(t, err)
	_, err = ConvertHDFToOCSF([]byte(`{"foo":1}`), converterVersion)
	assert.Error(t, err, "missing baselines must error")
}

func TestConvert_ClassRouting(t *testing.T) {
	// compliance fixture -> Compliance Finding (2003)
	out, err := ConvertHDFToOCSF(fixture(t, "input", "compliance.json"), converterVersion)
	require.NoError(t, err)
	for _, o := range parseLines(t, out) {
		assert.Equal(t, float64(2003), o["class_uid"])
		assert.Equal(t, float64(2), o["category_uid"])
		assert.Equal(t, float64(200301), o["type_uid"])
		assert.NotNil(t, o["compliance"], "compliance finding carries a compliance object")
		_, hasVuln := o["vulnerabilities"]
		assert.False(t, hasVuln)
	}
	// cve fixture -> Vulnerability Finding (2002)
	out, err = ConvertHDFToOCSF(fixture(t, "input", "cve.json"), converterVersion)
	require.NoError(t, err)
	for _, o := range parseLines(t, out) {
		assert.Equal(t, float64(2002), o["class_uid"])
		assert.Equal(t, float64(200201), o["type_uid"])
		assert.NotNil(t, o["vulnerabilities"])
		_, hasComp := o["compliance"]
		assert.False(t, hasComp)
	}
}

// TestConvert_RawPrimaryOverride is the crux: a waived failure keeps
// compliance.status_id = Fail (never masked as Pass) and marks the override on
// the lifecycle status_id = Suppressed.
func TestConvert_RawPrimaryOverride(t *testing.T) {
	out, err := ConvertHDFToOCSF(fixture(t, "input", "override.json"), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 1)
	o := objs[0]

	assert.Equal(t, float64(3), sub(t, o, "compliance")["status_id"], "raw verdict stays Fail even when waived")
	assert.Equal(t, "Fail", sub(t, o, "compliance")["status"], "compliance.status = OCSF caption of status_id")
	assert.Equal(t, float64(3), o["status_id"], "waiver (raw-failing → non-failing) -> lifecycle status_id Suppressed")
	assert.Equal(t, "waiver: Risk accepted per ISSM approval — compensating control in place", o["comment"],
		"comment = disposition + the required free-text reason")
	// lossless: full requirement (incl. the override chain) in unmapped
	assert.NotNil(t, sub(t, o, "unmapped")["hdf_requirement"])
}

// TestConvert_RiskAdjustStaysNew pins the disposition-branch: a risk-adjusted
// failure keeps compliance.status_id = Fail AND lifecycle status_id = New — it
// is still actionable, not suppressed (only its impact was re-scored).
func TestConvert_RiskAdjustStaysNew(t *testing.T) {
	out, err := ConvertHDFToOCSF(fixture(t, "input", "riskadjust.json"), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 1)
	o := objs[0]
	assert.Equal(t, float64(3), sub(t, o, "compliance")["status_id"], "raw verdict Fail")
	assert.Equal(t, "Fail", sub(t, o, "compliance")["status"])
	assert.Equal(t, float64(1), o["status_id"], "risk adjustment stays New (actionable), NOT Suppressed")
}

// TestConsumerQuery_ActionableFailures encodes the ADR addendum's canonical
// query: a real open fail is compliance.status_id=3 AND status_id IN (1,2);
// a waived fail (status_id=3) must be excluded.
func TestConsumerQuery_ActionableFailures(t *testing.T) {
	actionable := func(o map[string]interface{}) bool {
		comp, _ := o["compliance"].(map[string]interface{})
		if comp == nil {
			return false
		}
		return comp["status_id"] == float64(3) && (o["status_id"] == float64(1) || o["status_id"] == float64(2))
	}
	// compliance fixture: SV-204393 failed (open), SV-204405 passed, SV-204424 failed (open)
	out, _ := ConvertHDFToOCSF(fixture(t, "input", "compliance.json"), converterVersion)
	open := 0
	for _, o := range parseLines(t, out) {
		if actionable(o) {
			open++
		}
	}
	assert.Equal(t, 2, open, "two open failures, no waivers in this fixture")

	// override fixture: the single failure is waived -> NOT actionable
	out, _ = ConvertHDFToOCSF(fixture(t, "input", "override.json"), converterVersion)
	for _, o := range parseLines(t, out) {
		assert.False(t, actionable(o), "a waived failure must not be actionable")
	}
}

func TestConvert_ComplianceChecks(t *testing.T) {
	out, err := ConvertHDFToOCSF(fixture(t, "input", "compliance.json"), converterVersion)
	require.NoError(t, err)
	o := parseLines(t, out)[0]
	comp := sub(t, o, "compliance")
	checks, ok := comp["checks"].([]interface{})
	require.True(t, ok, "compliance.checks[] present")
	require.NotEmpty(t, checks)
	first := checks[0].(map[string]interface{})
	assert.Equal(t, comp["control"], first["uid"], "first check uid is the control id")
	assert.Contains(t, comp["standards"], "NIST SP 800-53")
}

func TestConvert_CVE(t *testing.T) {
	out, err := ConvertHDFToOCSF(fixture(t, "input", "cve.json"), converterVersion)
	require.NoError(t, err)
	for _, o := range parseLines(t, out) {
		vulns := o["vulnerabilities"].([]interface{})
		require.Len(t, vulns, 1)
		cve := vulns[0].(map[string]interface{})["cve"].(map[string]interface{})
		assert.Contains(t, cve["uid"], "CVE-")
		cvss := cve["cvss"].([]interface{})
		require.NotEmpty(t, cvss)
		first := cvss[0].(map[string]interface{})
		_, ok := first["base_score"].(float64)
		assert.True(t, ok, "cvss.base_score is a number")
		assert.NotEmpty(t, first["version"], "cvss.version is required")
	}
}

func TestConvert_GoldenParity(t *testing.T) {
	for _, name := range []string{"compliance", "cve", "override", "riskadjust", "warnings"} {
		out, err := ConvertHDFToOCSF(fixture(t, "input", name+".json"), converterVersion)
		require.NoError(t, err)
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			goldenPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-ocsf", "fixtures", "expected", name+".ndjson")
			require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
			continue
		}
		want := fixture(t, "expected", name+".ndjson")
		assert.Equal(t, string(want), string(out), "golden mismatch for %s", name)
	}
}

func TestSeverityID(t *testing.T) {
	mk := func(impact float64) map[string]interface{} { return map[string]interface{}{"impact": impact} }
	assert.Equal(t, 5, severityID(mk(1.0)))
	assert.Equal(t, 5, severityID(mk(0.9)))
	assert.Equal(t, 4, severityID(mk(0.7)))
	assert.Equal(t, 3, severityID(mk(0.5)))
	assert.Equal(t, 2, severityID(mk(0.1)))
	assert.Equal(t, 1, severityID(mk(0.0)))
	assert.Equal(t, 4, severityID(map[string]interface{}{"severity": "high"}))
	assert.Equal(t, 0, severityID(map[string]interface{}{}))
}

func TestComplianceStatusID(t *testing.T) {
	assert.Equal(t, 1, complianceStatusID("passed"))
	assert.Equal(t, 3, complianceStatusID("failed"))
	assert.Equal(t, 2, complianceStatusID("error"))
	assert.Equal(t, 2, complianceStatusID("notApplicable"))
	assert.Equal(t, 2, complianceStatusID("notReviewed"))
}

func TestOSTypeID(t *testing.T) {
	assert.Equal(t, 100, osTypeID("Windows Server 2019"))
	assert.Equal(t, 200, osTypeID("Red Hat Enterprise Linux 8"))
	assert.Equal(t, 200, osTypeID("Ubuntu 22.04"))
	assert.Equal(t, 300, osTypeID("macOS 14 Sonoma"))
	assert.Equal(t, 300, osTypeID("Darwin Kernel"))
	assert.Equal(t, 0, osTypeID("SomeAppliance"))
}

func TestSeverityIDFromString(t *testing.T) {
	assert.Equal(t, 5, severityIDFromString("critical"))
	assert.Equal(t, 4, severityIDFromString("High"))
	assert.Equal(t, 3, severityIDFromString("medium"))
	assert.Equal(t, 2, severityIDFromString("low"))
	assert.Equal(t, 1, severityIDFromString("informational"))
	assert.Equal(t, 1, severityIDFromString("info"))
	assert.Equal(t, 1, severityIDFromString("none"))
	assert.Equal(t, 0, severityIDFromString(""))
	assert.Equal(t, 0, severityIDFromString("weird"))
}

func TestOverrideComment(t *testing.T) {
	assert.Equal(t, "", overrideComment(map[string]interface{}{}))
	assert.Equal(t, "waiver: ok", overrideComment(map[string]interface{}{
		"disposition":     "waiver",
		"statusOverrides": []interface{}{map[string]interface{}{"reason": "ok"}},
	}))
	assert.Equal(t, "waiver", overrideComment(map[string]interface{}{"disposition": "waiver"}))
	assert.Equal(t, "r", overrideComment(map[string]interface{}{
		"statusOverrides": []interface{}{map[string]interface{}{"reason": "r"}},
	}))
}

// TestConvert_EdgeBranches exercises the vuln/device/metadata edge paths the
// three fixtures don't reach, via minimal synthesized inputs.
func TestConvert_EdgeBranches(t *testing.T) {
	// non-CVE cvss source -> cve.uid falls back to req id; cwe -> related_cwes; refs -> references
	doc := `{"baselines":[{"name":"b","requirements":[{"id":"GHSA-x","impact":0.5,"cvss":[{"baseScore":7.5,"version":"3.1","source":"GHSA-x-y"}],"cwe":["CWE-79"],"refs":[{"url":"https://a"}],"results":[{"status":"failed","codeDesc":"c","startTime":"2024-01-01T00:00:00Z"}]}]}]}`
	out, err := ConvertHDFToOCSF([]byte(doc), converterVersion)
	require.NoError(t, err)
	vuln := parseLines(t, out)[0]["vulnerabilities"].([]interface{})[0].(map[string]interface{})
	cve := vuln["cve"].(map[string]interface{})
	assert.Equal(t, "GHSA-x", cve["uid"], "non-CVE source falls back to requirement id")
	assert.NotNil(t, cve["related_cwes"])
	assert.NotNil(t, vuln["references"])

	// component with no identifying attribute -> no device
	doc2 := `{"components":[{"description":"x"}],"baselines":[{"name":"b","requirements":[{"id":"X","impact":0.5,"results":[{"status":"failed","codeDesc":"c","startTime":"2024-01-01T00:00:00Z"}]}]}]}`
	out, err = ConvertHDFToOCSF([]byte(doc2), converterVersion)
	require.NoError(t, err)
	_, hasDevice := parseLines(t, out)[0]["device"]
	assert.False(t, hasDevice)

	// generator fallback + Warning status + sentinel time (OCSF-required, so present)
	doc3 := `{"generator":{"name":"grype-to-hdf","version":"1.0"},"baselines":[{"name":"b","requirements":[{"id":"X","impact":0.5,"results":[{"status":"notReviewed","codeDesc":"c"}]}]}]}`
	out, err = ConvertHDFToOCSF([]byte(doc3), converterVersion)
	require.NoError(t, err)
	o := parseLines(t, out)[0]
	assert.Equal(t, float64(2), sub(t, o, "compliance")["status_id"], "notReviewed -> Warning")
	assert.Equal(t, "grype-to-hdf", sub(t, sub(t, o, "metadata"), "product")["name"], "generator fallback")
	assert.Equal(t, float64(0), o["time"], "no parseable timestamp -> 0 sentinel (time is OCSF-required)")
}

// TestRequiredFieldsAlwaysPresent guards the OCSF-required attributes that were
// previously omittable: metadata.product (falls back to the exporter identity)
// and time (falls back to 0) even when the HDF has no tool/generator/timestamp.
func TestRequiredFieldsAlwaysPresent(t *testing.T) {
	doc := `{"baselines":[{"name":"b","requirements":[{"id":"X","impact":0.5,"results":[{"status":"failed","codeDesc":"c"}]}]}]}`
	out, err := ConvertHDFToOCSF([]byte(doc), converterVersion)
	require.NoError(t, err)
	o := parseLines(t, out)[0]
	product := sub(t, sub(t, o, "metadata"), "product")
	assert.Equal(t, "hdf-to-ocsf", product["name"], "metadata.product falls back to exporter identity")
	assert.Equal(t, converterVersion, product["version"])
	_, hasTime := o["time"]
	assert.True(t, hasTime, "time (OCSF-required) always present")
}

func TestConvert_VulnFindingFrameworkTags(t *testing.T) {
	// A CVE finding that also carries NIST/CCI tags routes to a Vulnerability
	// Finding (which has no compliance.checks[]); the framework mapping rides on
	// finding_info.tags so it stays queryable rather than buried in unmapped.
	cveDoc := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"CVE-2024-1","impact":0.7,` +
		`"cvss":[{"baseScore":7.5,"source":"CVE-2024-1"}],"tags":{"nist":["SI-2","RA-5"],"cci":["CCI-000366"]},` +
		`"results":[{"status":"failed","codeDesc":"c","startTime":"2024-01-01T00:00:00Z"}]}]}]}`)
	out, err := ConvertHDFToOCSF(cveDoc, converterVersion)
	require.NoError(t, err)
	o := parseLines(t, out)[0]
	assert.Equal(t, float64(classVulnerability), o["class_uid"])
	tags, ok := sub(t, o, "finding_info")["tags"].([]interface{})
	require.True(t, ok, "vuln finding carries finding_info.tags")
	require.Len(t, tags, 2)
	nist := tags[0].(map[string]interface{})
	assert.Equal(t, "nist", nist["name"])
	assert.Equal(t, []interface{}{"SI-2", "RA-5"}, nist["values"])

	// A compliance finding maps frameworks via compliance.checks[], NOT finding_info.tags.
	compDoc := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"V-1","impact":0.5,"tags":{"nist":["AC-6"]},` +
		`"results":[{"status":"failed","codeDesc":"c","startTime":"2024-01-01T00:00:00Z"}]}]}]}`)
	out, err = ConvertHDFToOCSF(compDoc, converterVersion)
	require.NoError(t, err)
	c := parseLines(t, out)[0]
	_, hasTags := sub(t, c, "finding_info")["tags"]
	assert.False(t, hasTags, "compliance finding uses compliance.checks[], not finding_info.tags")
	assert.NotNil(t, sub(t, c, "compliance")["checks"])
}

func TestConvert_WarningStatuses(t *testing.T) {
	// notApplicable / notReviewed / error all roll up to compliance.status_id 2
	// (Warning), status caption "Warning", and stay New (not suppressed).
	out, err := ConvertHDFToOCSF(fixture(t, "input", "warnings.json"), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 3)
	for _, o := range objs {
		assert.Equal(t, float64(2003), o["class_uid"])
		assert.Equal(t, float64(2), sub(t, o, "compliance")["status_id"])
		assert.Equal(t, "Warning", sub(t, o, "compliance")["status"])
		assert.Equal(t, float64(1), o["status_id"], "warnings are not suppressed")
	}
}

func TestConvert_FloatBaseScore(t *testing.T) {
	// A whole-number CVSS base score must serialize as OCSF float_t: 10.0, not 10.
	doc := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"CVE-x","impact":0.7,` +
		`"cvss":[{"baseScore":10,"version":"3.1","source":"CVE-x"}],` +
		`"results":[{"status":"failed","codeDesc":"c","startTime":"2024-01-01T00:00:00Z"}]}]}]}`)
	out, err := ConvertHDFToOCSF(doc, converterVersion)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"base_score":10.0`, "whole-number base_score renders with a decimal")
	assert.NotContains(t, string(out), `"base_score":10,`, "must not emit an integer-shaped base_score")
}
