package nexusiq

import (
	"encoding/json"
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decoded(t *testing.T, name string) any {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal(fixture(t, name), &v))
	return v
}

func nexusFP(t *testing.T) registry.ConverterFingerprint {
	t.Helper()
	fp := registry.GetFingerprint("nexusiq-to-hdf")
	require.NotNil(t, fp, "nexusiq-to-hdf fingerprint not registered")
	return *fp
}

func TestFingerprintRegistered(t *testing.T) {
	fp := nexusFP(t)
	assert.Equal(t, "Nexus IQ", fp.Label)
	assert.Equal(t, registry.DirectionIngest, fp.Direction)
	assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
	assert.Equal(t, registry.OutputResults, fp.OutputType)
}

func TestFingerprintMatchesResultFiles(t *testing.T) {
	fp := nexusFP(t)
	assert.Equal(t, 1.0, fp.Fingerprint(decoded(t, "policy-evaluation.json")))
	assert.Equal(t, 0.9, fp.Fingerprint(decoded(t, "empty.json")), "a clean scan has no alert to confirm with")
}

func TestFingerprintRejectsOtherShapes(t *testing.T) {
	fp := nexusFP(t)
	cases := map[string]any{
		"not an object":       "a string",
		"nil":                 nil,
		"array":               []any{},
		"no applicationId":    map[string]any{"scanId": "s", "policyEvaluationResult": map[string]any{}},
		"no scanId":           map[string]any{"applicationId": "a", "policyEvaluationResult": map[string]any{}},
		"no evaluation":       map[string]any{"applicationId": "a", "scanId": "s"},
		"evaluation an array": map[string]any{"applicationId": "a", "scanId": "s", "policyEvaluationResult": []any{}},
		"gitlab-shaped":       map[string]any{"version": "15.0.0", "vulnerabilities": []any{}, "scan": map[string]any{}},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) { assert.Equal(t, 0.0, fp.Fingerprint(in)) })
	}
}

func TestFingerprintAlertWithoutViolationIDIsWeaker(t *testing.T) {
	obj := map[string]any{"applicationId": "a", "scanId": "s", "policyEvaluationResult": map[string]any{
		"alerts": []any{map[string]any{"trigger": map[string]any{}}},
	}}
	assert.Equal(t, 0.9, fingerprintObject(obj))
}
