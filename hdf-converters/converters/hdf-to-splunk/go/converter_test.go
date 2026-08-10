package hdftosplunk

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
	p := filepath.Join(shared.GetConvertersDir(), "hdf-to-splunk", "fixtures", kind, name)
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
	_, err := ConvertHDFToSplunk([]byte(""), converterVersion)
	assert.Error(t, err)
	_, err = ConvertHDFToSplunk([]byte("not json"), converterVersion)
	assert.Error(t, err)
	_, err = ConvertHDFToSplunk([]byte(`{"foo":1}`), converterVersion)
	assert.Error(t, err, "missing baselines must error")
}

func TestConvert_HECEnvelope(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixture(t, "input", "compliance.json"), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 3)

	for _, o := range objs {
		assert.Equal(t, "hdf:results", o["sourcetype"], "stable sourcetype is the TA contract")
		assert.Equal(t, "hdf-exporter", o["source"])
		assert.NotNil(t, o["event"], "event payload present")
		fields := sub(t, o, "fields")
		event := sub(t, o, "event")
		// hot CIM scalars mirrored into indexed fields
		assert.Equal(t, event["signature"], fields["signature"])
		assert.Equal(t, event["hdf_status"], fields["hdf_status"])
		assert.Equal(t, event["severity"], fields["severity"])
		// pure compliance carries no cvss/cve
		_, hasCVSS := event["cvss"]
		assert.False(t, hasCVSS, "compliance event has no cvss")
		_, hasCVE := event["cve"]
		assert.False(t, hasCVE)
	}
}

func TestConvert_ComplianceSeverityAndStatus(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixture(t, "input", "compliance.json"), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)

	// SV-204393 failed, SV-204405 passed, SV-204424 failed
	byID := map[string]map[string]interface{}{}
	for _, o := range objs {
		e := sub(t, o, "event")
		byID[e["signature_id"].(string)] = e
	}
	assert.Equal(t, "failed", byID["SV-204393"]["hdf_status"])
	assert.Equal(t, "passed", byID["SV-204405"]["hdf_status"])
	// CIM severity is one of the enum values
	for _, e := range byID {
		assert.Contains(t, []string{"critical", "high", "medium", "low", "informational"}, e["severity"])
		// lossless hdf.* block present
		hdf := sub(t, e, "hdf")
		assert.Equal(t, converterVersion, hdf["exporter_version"])
		assert.NotNil(t, hdf["nist"])
	}
}

func TestConvert_CVE(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixture(t, "input", "cve.json"), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 3)

	for _, o := range objs {
		e := sub(t, o, "event")
		cve, _ := e["cve"].(string)
		assert.Contains(t, cve, "CVE-", "cve populated for CVE findings")
		cvss, ok := e["cvss"].(float64)
		require.True(t, ok, "cvss is a single number")
		assert.GreaterOrEqual(t, cvss, 0.0)
		assert.LessOrEqual(t, cvss, 10.0, "cvss within valid CVSS range")
		// cvss mirrored into indexed fields
		assert.Equal(t, cvss, sub(t, o, "fields")["cvss"])
	}
}

func TestConvert_OverridePromotedAndTimeEpoch(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixture(t, "input", "override.json"), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 1)
	o := objs[0]

	// HEC time is integer epoch seconds (2024-01-01T00:00:00Z)
	tm, ok := o["time"].(float64)
	require.True(t, ok, "time present as a number")
	assert.Equal(t, float64(1704067200), tm)
	assert.Equal(t, "rhel9-server-01", o["host"])

	e := sub(t, o, "event")
	// raw-primary: hdf_status carries the RAW verdict (waived fail stays failed);
	// suppressed is the acceptance axis, promoted to both event and indexed fields
	assert.Equal(t, "failed", e["hdf_status"], "raw verdict drives hdf_status")
	assert.Equal(t, true, e["suppressed"], "waiver → suppressed")
	assert.Equal(t, true, sub(t, o, "fields")["suppressed"], "suppressed mirrored into indexed fields")
	hdf := sub(t, e, "hdf")
	assert.Equal(t, "failed", hdf["status"], "lossless raw status preserved")
	assert.Equal(t, true, hdf["suppressed"], "lossless suppressed axis in hdf.*")
	assert.Equal(t, "passed", hdf["effective_status"])
	assert.Equal(t, "waiver", hdf["disposition"])
	assert.Equal(t, true, hdf["overridden"])
}

// TestConvert_RiskAdjustStaysActionable pins the disposition-branch: a risk-
// adjusted failure is NOT suppressed, so it remains in the Vulnerabilities model.
func TestConvert_RiskAdjustStaysActionable(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixture(t, "input", "riskadjust.json"), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 1)
	e := sub(t, objs[0], "event")
	assert.Equal(t, "failed", e["hdf_status"], "risk-adjusted failure stays failed")
	assert.Equal(t, false, e["suppressed"], "risk adjustment does NOT suppress")
	assert.Equal(t, false, sub(t, objs[0], "fields")["suppressed"])
}

// TestConvert_AugmentedHDFFields pins the exportmap-block keys the shared
// passthrough omits but splunk-to-hdf round-trips: source_location,
// verification_method, baseline version/title/checksum/groups, and the full
// component. Each must appear only when the source carries it.
func TestConvert_AugmentedHDFFields(t *testing.T) {
	out, err := ConvertHDFToSplunk(fixture(t, "input", "override.json"), converterVersion)
	require.NoError(t, err)
	hdf := sub(t, sub(t, parseLines(t, out)[0], "event"), "hdf")

	// source_location round-trips {ref, line}.
	sl := hdf["source_location"].(map[string]interface{})
	assert.Equal(t, "controls/stig.rb", sl["ref"])
	assert.Equal(t, float64(1), sl["line"])

	// baseline metadata beyond name.
	assert.Equal(t, "1.0.0", hdf["baseline_version"])
	assert.Equal(t, "RHEL 9 STIG Baseline", hdf["baseline_title"])
	ck := hdf["baseline_checksum"].(map[string]interface{})
	assert.Equal(t, "sha256", ck["algorithm"])
	assert.Equal(t, "abc123", ck["value"])
	groups := hdf["groups"].([]interface{})
	require.Len(t, groups, 1)
	assert.Equal(t, "controls/stig.rb", groups[0].(map[string]interface{})["id"])

	// full component, plus CIM promotions on event/fields.
	comp := hdf["component"].(map[string]interface{})
	assert.Equal(t, "8f3b2c1a-0000-4a00-8000-000000000001", comp["componentId"])
	assert.Equal(t, "10.0.0.50", comp["ipAddress"])
	assert.Equal(t, "Red Hat Enterprise Linux 9", comp["osName"])
	assert.Equal(t, "9.3", comp["osVersion"])
	e := sub(t, parseLines(t, out)[0], "event")
	assert.Equal(t, "Red Hat Enterprise Linux 9", e["os"])
	assert.Equal(t, "10.0.0.50", e["dest_ip"])
	assert.Equal(t, "10.0.0.50", sub(t, parseLines(t, out)[0], "fields")["dest_ip"])

	// verificationMethod is absent here, so no key is emitted.
	_, hasVM := hdf["verification_method"]
	assert.False(t, hasVM, "verification_method omitted when source lacks it")

	// verification_method carries through where the source has it.
	cveOut, err := ConvertHDFToSplunk(fixture(t, "input", "cve.json"), converterVersion)
	require.NoError(t, err)
	cveHDF := sub(t, sub(t, parseLines(t, cveOut)[0], "event"), "hdf")
	assert.Equal(t, "automated", cveHDF["verification_method"])
	// cve baseline has version but no title/checksum/groups → those stay absent.
	assert.Equal(t, "1.0.0", cveHDF["baseline_version"])
	_, hasTitle := cveHDF["baseline_title"]
	assert.False(t, hasTitle)
	_, hasGroups := cveHDF["groups"]
	assert.False(t, hasGroups)
}

func TestConvert_GoldenParity(t *testing.T) {
	// The expected .ndjson files are the shared TS<->Go golden contract.
	for _, name := range []string{"compliance", "cve", "override", "riskadjust"} {
		out, err := ConvertHDFToSplunk(fixture(t, "input", name+".json"), converterVersion)
		require.NoError(t, err)
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			goldenPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-splunk", "fixtures", "expected", name+".ndjson")
			require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
			continue
		}
		want := fixture(t, "expected", name+".ndjson")
		assert.Equal(t, string(want), string(out), "golden mismatch for %s", name)
	}
}

func TestSeverity_ImpactBands(t *testing.T) {
	mk := func(impact float64) map[string]interface{} {
		return map[string]interface{}{"impact": impact}
	}
	assert.Equal(t, "critical", severity(mk(1.0)))
	assert.Equal(t, "critical", severity(mk(0.9)))
	assert.Equal(t, "high", severity(mk(0.7)))
	assert.Equal(t, "medium", severity(mk(0.5)))
	assert.Equal(t, "low", severity(mk(0.1)))
	assert.Equal(t, "low", severity(mk(0.05))) // any impact >0 is low; only 0.0 is informational (shared banding)
	assert.Equal(t, "informational", severity(mk(0.0)))
	// no impact -> normalize the source severity string
	assert.Equal(t, "high", severity(map[string]interface{}{"severity": "high"}))
	assert.Equal(t, "informational", severity(map[string]interface{}{"severity": "none"}))
	assert.Equal(t, "informational", severity(map[string]interface{}{}))
}

// TestTAContract guards the exporter<->Splunk_TA_hdf contract: the TA does no
// field aliasing, so its eventtype/tags and the CIM Vulnerabilities model depend
// on the exporter emitting these exact field names. A rename here would silently
// break CIM normalization, so pin them.
func TestTAContract(t *testing.T) {
	// eventtype discriminators (eventtypes.conf) + CIM Vulnerabilities fields.
	out, err := ConvertHDFToSplunk(fixture(t, "input", "cve.json"), converterVersion)
	require.NoError(t, err)
	for _, o := range parseLines(t, out) {
		e := sub(t, o, "event")
		for _, f := range []string{"signature", "signature_id", "severity", "dest", "cve", "cvss", "vendor_product", "hdf_status", "suppressed"} {
			_, ok := e[f]
			assert.True(t, ok, "CVE event must carry TA/CIM field %q", f)
		}
	}
	// compliance findings drive the eventtype via hdf_status (no cve/cvss).
	out, err = ConvertHDFToSplunk(fixture(t, "input", "compliance.json"), converterVersion)
	require.NoError(t, err)
	for _, o := range parseLines(t, out) {
		e := sub(t, o, "event")
		for _, f := range []string{"signature", "signature_id", "severity", "dest", "hdf_status", "suppressed"} {
			_, ok := e[f]
			assert.True(t, ok, "compliance event must carry TA/CIM field %q", f)
		}
	}

	// The TA's finding eventtype must exclude suppressed=true so a waived/FP
	// control drops out of the CIM Vulnerabilities model. Pin the static clause
	// so a config edit can't silently re-admit accepted risk.
	confPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-splunk", "Splunk_TA_hdf", "default", "eventtypes.conf")
	conf, err := os.ReadFile(confPath)
	require.NoError(t, err, "read eventtypes.conf")
	assert.Contains(t, string(conf), "NOT suppressed=true", "TA eventtype must exclude suppressed=true")
}

func TestConvert_CategoryFromCWE(t *testing.T) {
	doc := `{"baselines":[{"name":"b","requirements":[{"id":"X","title":"t","impact":0.5,"cwe":["CWE-79","CWE-89"],"results":[{"status":"failed","codeDesc":"c","startTime":"2024-01-01T00:00:00Z"}]}]}]}`
	out, err := ConvertHDFToSplunk([]byte(doc), converterVersion)
	require.NoError(t, err)
	objs := parseLines(t, out)
	require.Len(t, objs, 1)
	assert.Equal(t, "CWE-79", sub(t, objs[0], "event")["category"], "category is the first cwe id")
}

func TestMaxCVSS(t *testing.T) {
	req := map[string]interface{}{"cvss": []interface{}{
		map[string]interface{}{"baseScore": 5.3},
		map[string]interface{}{"baseScore": 9.8},
		map[string]interface{}{"baseScore": 7.1},
	}}
	v, ok := maxCVSS(req)
	assert.True(t, ok)
	assert.Equal(t, 9.8, v)
	_, ok = maxCVSS(map[string]interface{}{})
	assert.False(t, ok)
}
