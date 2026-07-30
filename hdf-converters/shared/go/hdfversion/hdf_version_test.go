package hdfversion

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
)

func convertersDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "converters")
}

func legacyhdfFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(convertersDir(), "legacyhdf-to-hdf", "fixtures", "input", name)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

// Version identifiers: v2 = legacy Heimdall schema (profiles/platform),
// v3 = modern hdf-libs schema (baselines/components). There is no HDF v1
// transform (v1 = raw InSpec; see NormalizeVersion).

func TestTransformHDF_LegacyToModern(t *testing.T) {
	legacyInput := legacyhdfFixture(t, "minimal.json")

	output, _, err := TransformHDF(legacyInput, LegacyVersion, ModernVersion)
	require.NoError(t, err)
	require.NotEmpty(t, output)

	// Output should be valid JSON with modern (v3) structure.
	var modern map[string]any
	require.NoError(t, json.Unmarshal(output, &modern))
	assert.Contains(t, modern, "baselines", "modern output should have baselines")
	assert.Contains(t, modern, "components", "modern output should have components")
	// Should NOT have legacy fields.
	assert.NotContains(t, modern, "profiles", "modern output should not have profiles")
	assert.NotContains(t, modern, "platform", "modern output should not have platform")
}

func TestTransformHDF_ModernToLegacy(t *testing.T) {
	// First get a modern document by upgrading a legacy one.
	legacyInput := legacyhdfFixture(t, "minimal.json")
	modernOutput, _, err := TransformHDF(legacyInput, LegacyVersion, ModernVersion)
	require.NoError(t, err)

	// Now downgrade back to the legacy shape.
	legacyOutput, _, err := TransformHDF(modernOutput, ModernVersion, LegacyVersion)
	require.NoError(t, err)
	require.NotEmpty(t, legacyOutput)

	// Output should have legacy (v2) structure.
	var legacy map[string]any
	require.NoError(t, json.Unmarshal(legacyOutput, &legacy))
	assert.Contains(t, legacy, "profiles", "legacy output should have profiles")
	assert.Contains(t, legacy, "platform", "legacy output should have platform")
	assert.Contains(t, legacy, "statistics", "legacy output should have statistics")
	// Should NOT have modern fields.
	assert.NotContains(t, legacy, "baselines", "legacy output should not have baselines")
	assert.NotContains(t, legacy, "components", "legacy output should not have components")
}

func TestTransformHDF_SameVersion(t *testing.T) {
	legacyInput := legacyhdfFixture(t, "minimal.json")

	// Same version should return input unchanged.
	output, _, err := TransformHDF(legacyInput, LegacyVersion, LegacyVersion)
	require.NoError(t, err)
	assert.JSONEq(t, string(legacyInput), string(output))
}

func TestTransformHDF_UnknownTransform(t *testing.T) {
	// "1" is not a transform key — raw InSpec is not a distinct schema version.
	_, _, err := TransformHDF([]byte(`{}`), "1", ModernVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no HDF transform")
}

func TestTransformHDF_InvalidJSON(t *testing.T) {
	_, _, err := TransformHDF([]byte(`not json`), LegacyVersion, ModernVersion)
	require.Error(t, err)
}

func TestTransformHDF_RoundTrip(t *testing.T) {
	legacyInput := legacyhdfFixture(t, "minimal.json")

	// legacy → modern → legacy should preserve core fields.
	modern, _, err := TransformHDF(legacyInput, LegacyVersion, ModernVersion)
	require.NoError(t, err)

	legacyAgain, _, err := TransformHDF(modern, ModernVersion, LegacyVersion)
	require.NoError(t, err)

	var original map[string]any
	var roundTripped map[string]any
	require.NoError(t, json.Unmarshal(legacyInput, &original))
	require.NoError(t, json.Unmarshal(legacyAgain, &roundTripped))

	origProfiles, _ := original["profiles"].([]any)
	rtProfiles, _ := roundTripped["profiles"].([]any)
	assert.Equal(t, len(origProfiles), len(rtProfiles), "profile count should survive round-trip")
}

func TestDowngradeV3ToV2_FlattensAmendments(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	input, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "testdata", "modern_with_amendments.json"))
	require.NoError(t, err)

	out, warnings, err := TransformHDF(input, ModernVersion, LegacyVersion)
	require.NoError(t, err)

	var legacy map[string]any
	require.NoError(t, json.Unmarshal(out, &legacy))

	// Incidental gap C: top-level version reconstructed from the source tool.
	assert.Equal(t, "5.22.65", legacy["version"])

	// The downgraded document must satisfy the InSpec exec-json schema Heimdall loads,
	// or the whole file is rejected. Assert every required key on every element and that
	// result statuses stay within InSpec's ControlResultStatus enum.
	assert.Contains(t, legacy["platform"], "release", "platform.release is InSpec-required")
	profile := legacy["profiles"].([]any)[0].(map[string]any)
	for _, k := range []string{"attributes", "controls", "groups", "name", "sha256", "supports"} {
		assert.Contains(t, profile, k, "InSpec-required profile field %q must be present", k)
	}
	controls := profile["controls"].([]any)
	validStatus := map[string]bool{"passed": true, "failed": true, "error": true, "skipped": true}
	byID := map[string]map[string]any{}
	for _, cv := range controls {
		c := cv.(map[string]any)
		byID[c["id"].(string)] = c
		for _, k := range []string{"id", "impact", "refs", "results", "source_location", "tags"} {
			assert.Contains(t, c, k, "control %v missing InSpec-required %q", c["id"], k)
		}
		for _, rv := range c["results"].([]any) {
			r := rv.(map[string]any)
			assert.Contains(t, r, "code_desc")
			assert.Contains(t, r, "start_time")
			assert.Truef(t, validStatus[r["status"].(string)], "result status %q is not a valid InSpec ControlResultStatus", r["status"])
		}
	}

	// Waiver: control status flattened to the effective outcome (passed), the raw
	// result verdict preserved (failed), and an audit breadcrumb in waiver_data.
	waiver := byID["V-001-waiver"]
	assert.Equal(t, "passed", waiver["status"], "control status is the effective (attested) outcome")
	wd := waiver["waiver_data"].(map[string]any)
	assert.Equal(t, "waiver", wd["override_type"])
	assert.Equal(t, true, wd["skipped_due_to_waiver"])
	assert.Contains(t, wd["message"], "Compensating control")
	rawStatus := waiver["results"].([]any)[0].(map[string]any)["status"]
	assert.Equal(t, "failed", rawStatus, "raw per-result verdict is preserved")

	// False positive: also flattened, breadcrumb records the disposition type.
	fp := byID["V-002-fp"]
	assert.Equal(t, "passed", fp["status"])
	assert.Equal(t, "falsePositive", fp["waiver_data"].(map[string]any)["override_type"])

	// POA&M: not representable — control stays failed, breadcrumb records it, warning names it.
	poam := byID["V-003-poam"]
	assert.Equal(t, "failed", poam["status"])
	assert.Contains(t, poam["waiver_data"].(map[string]any), "not_representable_in_v2")

	// riskAdjustment: the effective (re-scored) impact is what the v2 control shows.
	risk := byID["V-004-risk"]
	assert.InDelta(t, 0.3, risk["impact"].(float64), 1e-9)
	// Incidental gap C: InSpec resource fields carried onto the result.
	riskResult := risk["results"].([]any)[0].(map[string]any)
	assert.Equal(t, "file", riskResult["resource_class"])
	assert.Equal(t, "/etc/audit/auditd.conf", riskResult["resource_id"])
	// refs carried into the v2 refs slot; cwe/severity mirrored into tags for Heimdall.
	assert.NotEmpty(t, risk["refs"], "advisory refs are carried")
	riskTags := risk["tags"].(map[string]any)
	assert.Equal(t, []any{"CWE-79"}, riskTags["cweid"])
	assert.Equal(t, "medium", riskTags["severity"])

	// Part B: the non-representable POA&M is surfaced as a warning, not dropped silently.
	joined := strings.Join(warnings, "\n")
	assert.Contains(t, joined, "V-003-poam")
	assert.Contains(t, joined, "POA&M")
}

// TestDowngradeV3ToV2_ValidatesAgainstInspecSchema is the authoritative regression
// guard: the downgrade output must validate against the InSpec exec-json schema
// Heimdall's parser enforces (vendored in testdata). Field-presence assertions can
// drift from the real contract; validating the whole document against the schema
// cannot.
func TestDowngradeV3ToV2_ValidatesAgainstInspecSchema(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	testdata := filepath.Join(filepath.Dir(thisFile), "testdata")
	input, err := os.ReadFile(filepath.Join(testdata, "modern_with_amendments.json"))
	require.NoError(t, err)

	out, _, err := TransformHDF(input, ModernVersion, LegacyVersion)
	require.NoError(t, err)

	// Load the schema from bytes rather than a file:// reference loader — a Windows
	// absolute path (D:\...) does not form a valid file URI and fails to parse.
	schemaBytes, err := os.ReadFile(filepath.Join(testdata, "exec-json.schema.json"))
	require.NoError(t, err)

	result, err := gojsonschema.Validate(
		gojsonschema.NewBytesLoader(schemaBytes),
		gojsonschema.NewBytesLoader(out),
	)
	require.NoError(t, err)
	for _, e := range result.Errors() {
		t.Errorf("downgraded document violates InSpec exec-json schema: %s", e)
	}
}

func TestDowngradeV3ToV2_SkipsExpiredOverrideBreadcrumb(t *testing.T) {
	// A requirement whose only override has already expired must not name that
	// override in the waiver_data breadcrumb.
	input := []byte(`{
		"baselines": [{"name": "B", "requirements": [{
			"id": "V-EXP", "title": "Expired waiver", "impact": 0.5,
			"effectiveStatus": "failed",
			"statusOverrides": [{
				"type": "waiver", "status": "passed", "reason": "old waiver",
				"appliedBy": {"type": "username", "identifier": "jdoe"},
				"appliedAt": "2019-01-01T00:00:00Z", "expiresAt": "2020-01-01T00:00:00Z"
			}],
			"results": [{"status": "failed", "codeDesc": "x", "startTime": "2020-01-01T00:00:00Z"}]
		}]}],
		"components": [{"name": "h", "type": "host"}],
		"generator": {"name": "g", "version": "1.0.0"},
		"tool": {"name": "t", "version": "1.0.0"}
	}`)
	out, _, err := TransformHDF(input, ModernVersion, LegacyVersion)
	require.NoError(t, err)

	var legacy map[string]any
	require.NoError(t, json.Unmarshal(out, &legacy))
	c := legacy["profiles"].([]any)[0].(map[string]any)["controls"].([]any)[0].(map[string]any)
	wd, _ := c["waiver_data"].(map[string]any)
	assert.NotContains(t, wd, "override_type", "an expired override must not become the waiver_data breadcrumb")
}

func TestDetectHDFVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"legacy (v2) with profiles+platform", `{"version":"3.4.5","profiles":[],"platform":{"name":"test"}}`, LegacyVersion, false},
		{"modern (v3) with baselines+components", `{"baselines":[],"components":[]}`, ModernVersion, false},
		{"ambiguous", `{"version":"1.0"}`, "", true},
		{"invalid json", `not json`, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DetectHDFVersion([]byte(tt.input))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	// "1" has no distinct schema → maps to legacy (v2) with a warning.
	got, warn := NormalizeVersion("1")
	assert.Equal(t, LegacyVersion, got)
	assert.NotEmpty(t, warn, "hdf@1 should warn")

	// "2", "3", and "" pass through with no warning.
	for _, v := range []string{LegacyVersion, ModernVersion, ""} {
		got, warn := NormalizeVersion(v)
		assert.Equal(t, v, got)
		assert.Empty(t, warn, "hdf@%s should not warn", v)
	}

	// A leading "v" is accepted and stripped (users write "v3"/"v2").
	for _, v := range []string{"v2", "v3"} {
		got, warn := NormalizeVersion(v)
		assert.Equal(t, strings.TrimPrefix(v, "v"), got)
		assert.Empty(t, warn, "%s should normalize without warning", v)
	}
	// "v1" strips to "1" → legacy (v2) with the no-v1 warning.
	got, warn = NormalizeVersion("v1")
	assert.Equal(t, LegacyVersion, got)
	assert.NotEmpty(t, warn, "v1 should warn like 1")
}
