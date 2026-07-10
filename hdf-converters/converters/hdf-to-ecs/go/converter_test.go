package hdftoecs

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

func fixture(t *testing.T, kind, name string) []byte {
	t.Helper()
	p := filepath.Join(shared.GetConvertersDir(), "hdf-to-ecs", "fixtures", kind, name)
	data, err := os.ReadFile(p)
	require.NoError(t, err, "read fixture %s", p)
	return data
}

// parseLines splits NDJSON output into per-line decoded objects, asserting each
// line is a standalone JSON object.
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

func TestStatusToOutcome_Exhaustive(t *testing.T) {
	cases := map[string]string{
		"passed":        "success",
		"failed":        "failure",
		"notApplicable": "unknown",
		"notReviewed":   "unknown",
		"error":         "unknown",
	}
	for status, want := range cases {
		assert.Equal(t, want, statusToOutcome(status), "status %q", status)
	}
}

func TestConvertHDFToECS_EmptyAndInvalid(t *testing.T) {
	_, err := ConvertHDFToECS([]byte(""), converterVersion)
	assert.Error(t, err)
	_, err = ConvertHDFToECS([]byte("not json"), converterVersion)
	assert.Error(t, err)
	_, err = ConvertHDFToECS([]byte(`{"foo":1}`), converterVersion)
	assert.Error(t, err, "missing baselines must error")
}

func TestConvertHDFToECS_Compliance(t *testing.T) {
	out, err := ConvertHDFToECS(fixture(t, "input", "compliance.json"), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 3, "3 requirements -> 3 events")

	// event.outcome mapping: SV-204393 failed, SV-204405 passed, SV-204424 failed
	wantOutcome := map[string]string{"SV-204393": "failure", "SV-204405": "success", "SV-204424": "failure"}
	for _, o := range objs {
		assert.Equal(t, "9.4.0", sub(t, o, "ecs")["version"])
		event := sub(t, o, "event")
		rule := sub(t, o, "rule")
		id := rule["id"].(string)
		assert.Equal(t, wantOutcome[id], event["outcome"], "outcome for %s", id)
		assert.Equal(t, "state", event["kind"])
		assert.Equal(t, "Red Hat Enterprise Linux 7 Security Technical Implementation Guide", rule["ruleset"])
		assert.Equal(t, "003.005", rule["version"])
		// host projected from the single host component
		host := sub(t, o, "host")
		assert.Equal(t, "localhost.localdomain", host["name"])
		assert.Equal(t, "127.0.0.1", host["ip"])
		// observer from XCCDF tool
		observer := sub(t, o, "observer")
		assert.Equal(t, "XCCDF", observer["name"])
		assert.Equal(t, "scanner", observer["type"])
		// pure compliance -> no vulnerability block
		_, hasVuln := o["vulnerability"]
		assert.False(t, hasVuln, "compliance event must not carry vulnerability.*")
		// hdf lossless block: nist/cci present, status lossless
		hdf := sub(t, o, "hdf")
		assert.NotNil(t, hdf["nist"], "hdf.nist present")
		assert.NotNil(t, hdf["cci"], "hdf.cci present")
		assert.Equal(t, converterVersion, hdf["exporter_version"])
		// event.category is exactly ["configuration"]
		assert.Equal(t, []interface{}{"configuration"}, event["category"])
	}
}

func TestConvertHDFToECS_CVE(t *testing.T) {
	out, err := ConvertHDFToECS(fixture(t, "input", "cve.json"), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 3)

	for _, o := range objs {
		event := sub(t, o, "event")
		// event.category includes "vulnerability"
		assert.Contains(t, event["category"], "vulnerability")
		vuln := sub(t, o, "vulnerability")
		id, _ := vuln["id"].(string)
		assert.True(t, strings.HasPrefix(id, "CVE-"), "vulnerability.id should be a CVE: %v", id)
		assert.Equal(t, "CVE", vuln["enumeration"])
		assert.Equal(t, "CVSS", vuln["classification"])
		score := sub(t, o, "vulnerability")["score"].(map[string]interface{})
		assert.NotNil(t, score["base"], "vulnerability.score.base present")
		scanner := vuln["scanner"].(map[string]interface{})
		assert.Equal(t, "Nessus", scanner["vendor"])
	}
}

func TestConvertHDFToECS_Override(t *testing.T) {
	out, err := ConvertHDFToECS(fixture(t, "input", "override.json"), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 1)
	o := objs[0]

	// raw-primary: the result is failed and a waiver makes effectiveStatus passed,
	// but event.outcome follows the RAW verdict (a waived failure is still failure);
	// hdf.suppressed carries the acceptance axis.
	assert.Equal(t, "failure", sub(t, o, "event")["outcome"], "raw verdict drives event.outcome")

	hdf := sub(t, o, "hdf")
	assert.Equal(t, "failed", hdf["status"], "hdf.status is the lossless raw status")
	assert.Equal(t, true, hdf["suppressed"], "waiver → hdf.suppressed true")
	assert.Equal(t, "passed", hdf["effective_status"], "hdf.effective_status is the override outcome")
	assert.Equal(t, "waiver", hdf["disposition"], "hdf.disposition promoted flat")
	assert.Equal(t, true, hdf["overridden"])
	overrides, ok := hdf["status_overrides"].([]interface{})
	require.True(t, ok, "hdf.status_overrides present")
	require.Len(t, overrides, 1)
	first := overrides[0].(map[string]interface{})
	assert.Equal(t, "waiver", first["type"])

	// host projected from the component (with componentId -> host.id)
	host := sub(t, o, "host")
	assert.Equal(t, "rhel9-server-01", host["name"])
	assert.Equal(t, "8f3b2c1a-0000-4a00-8000-000000000001", host["id"])
	// no tool/generator on this fixture -> observer omitted (graceful degradation)
	_, hasObserver := o["observer"]
	assert.False(t, hasObserver, "observer omitted when no tool/generator")
}

// TestConvertHDFToECS_RiskAdjustStaysActionable pins the disposition-branch: a
// risk-adjusted failure keeps event.outcome=failure AND hdf.suppressed=false —
// still actionable, only its impact was re-scored.
func TestConvertHDFToECS_RiskAdjustStaysActionable(t *testing.T) {
	out, err := ConvertHDFToECS(fixture(t, "input", "riskadjust.json"), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 1)
	o := objs[0]
	assert.Equal(t, "failure", sub(t, o, "event")["outcome"], "risk-adjusted failure is still failure")
	hdf := sub(t, o, "hdf")
	assert.Equal(t, false, hdf["suppressed"], "risk adjustment does NOT suppress")
	assert.Equal(t, "riskAdjustment", hdf["disposition"])
}

func TestConvertHDFToECS_ThreatFromAttackTags(t *testing.T) {
	// mitre_attack as an array and attack as a scalar string — both stringSlice branches.
	doc := `{"baselines":[{"name":"b","requirements":[{"id":"X","title":"t","tags":{"mitre_attack":["T1059","T1078"],"attack":"T1110"},"results":[{"status":"failed","codeDesc":"c","startTime":"2024-01-01T00:00:00Z"}]}]}]}`
	out, err := ConvertHDFToECS([]byte(doc), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 1)
	threat := sub(t, objs[0], "threat")
	assert.Equal(t, "MITRE ATT&CK", threat["framework"])
	techs, ok := threat["technique"].([]interface{})
	require.True(t, ok)
	require.Len(t, techs, 3)
	ids := []string{}
	for _, tc := range techs {
		ids = append(ids, tc.(map[string]interface{})["id"].(string))
	}
	assert.Equal(t, []string{"T1059", "T1078", "T1110"}, ids)
}

func TestConvertHDFToECS_ObserverGeneratorFallback(t *testing.T) {
	// No tool -> observer falls back to generator name/version.
	doc := `{"generator":{"name":"grype-to-hdf","version":"1.2.3"},"baselines":[{"name":"b","requirements":[{"id":"X","tags":{},"results":[{"status":"passed","codeDesc":"c","startTime":"2024-01-01T00:00:00Z"}]}]}]}`
	out, err := ConvertHDFToECS([]byte(doc), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 1)
	observer := sub(t, objs[0], "observer")
	assert.Equal(t, "grype-to-hdf", observer["name"])
	assert.Equal(t, "1.2.3", observer["version"])
	assert.Equal(t, "scanner", observer["type"])
	// generator-sourced observer has no product (that comes from tool.format)
	_, hasProduct := observer["product"]
	assert.False(t, hasProduct)
}

func TestConvertHDFToECS_NoResultsFallback(t *testing.T) {
	doc := `{"timestamp":"2025-01-01T00:00:00Z","baselines":[{"name":"b","requirements":[{"id":"X","tags":{},"results":[]}]}]}`
	out, err := ConvertHDFToECS([]byte(doc), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 1)
	assert.Equal(t, "2025-01-01T00:00:00Z", objs[0]["@timestamp"], "@timestamp falls back to doc timestamp")
	assert.Equal(t, "unknown", sub(t, objs[0], "event")["outcome"], "notReviewed -> unknown")
	assert.Equal(t, "notReviewed", sub(t, objs[0], "hdf")["status"])
}

func TestConvertHDFToECS_VulnIDFallback(t *testing.T) {
	// cvss without source -> vulnerability.id falls back to the requirement id, no enumeration.
	doc := `{"baselines":[{"name":"b","requirements":[{"id":"GHSA-abcd-1234","tags":{},"cvss":[{"baseScore":7.5,"version":"3.1"}],"results":[{"status":"failed","codeDesc":"c","startTime":"2024-01-01T00:00:00Z"}]}]}]}`
	out, err := ConvertHDFToECS([]byte(doc), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	vuln := sub(t, objs[0], "vulnerability")
	assert.Equal(t, "GHSA-abcd-1234", vuln["id"])
	_, hasEnum := vuln["enumeration"]
	assert.False(t, hasEnum, "non-CVE source has no enumeration")
}

func TestConvertHDFToECS_GracefulDegradation(t *testing.T) {
	// non-default descriptions, url-less refs, and a startTime-less result.
	doc := `{"timestamp":"2025-06-01T00:00:00Z","baselines":[{"name":"b","requirements":[{"id":"X","tags":{},"descriptions":[{"label":"rationale","data":"r"}],"refs":[{"name":"ref-without-url"}],"results":[{"status":"passed","codeDesc":"c"}]}]}]}`
	out, err := ConvertHDFToECS([]byte(doc), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 1)
	assert.Equal(t, "2025-06-01T00:00:00Z", objs[0]["@timestamp"], "result lacks startTime -> doc fallback")
	rule := sub(t, objs[0], "rule")
	_, hasDesc := rule["description"]
	assert.False(t, hasDesc, "no default description")
	_, hasRef := rule["reference"]
	assert.False(t, hasRef, "ref carries no url")
}

// TestGoldenParity asserts byte-for-byte output against frozen golden files.
// The TypeScript test asserts against the SAME files, guaranteeing TS↔Go parity.
func TestGoldenParity(t *testing.T) {
	for _, name := range []string{"compliance", "cve", "override", "riskadjust"} {
		out, err := ConvertHDFToECS(fixture(t, "input", name+".json"), converterVersion)
		require.NoError(t, err)
		goldenPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-ecs", "fixtures", "expected", name+".ndjson")
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
			continue
		}
		golden, err := os.ReadFile(goldenPath)
		require.NoError(t, err, "read golden %s", goldenPath)
		assert.Equal(t, string(golden), string(out), "golden mismatch for %s", name)
	}
}
