package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var sarifInput = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"test"}},"results":[]}]}`
var gosecInput = `{"GosecVersion":"2.18.2","Issues":[{"severity":"HIGH"}],"Stats":{"files":1}}`
var junitInput = `<?xml version="1.0"?><testsuites><testsuite name="s1"><testcase name="t1"/></testsuite></testsuites>`
var xccdfInput = `<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test"><status>incomplete</status></Benchmark>`

func registerTestFingerprints() {
	Register(ConverterFingerprint{
		ID: "sarif-to-hdf", Label: "SARIF",
		Direction: DirectionIngest, InputFamily: FamilyJSON, OutputType: OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			if _, hasVersion := obj["version"]; hasVersion {
				if _, hasRuns := obj["runs"]; hasRuns {
					if _, isStr := obj["version"].(string); isStr {
						if _, isArr := obj["runs"].([]any); isArr {
							return 0.9
						}
					}
				}
			}
			return 0
		},
	})
	Register(ConverterFingerprint{
		ID: "gosec-to-hdf", Label: "GoSec",
		Direction: DirectionIngest, InputFamily: FamilyJSON, OutputType: OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			_, hasVersion := obj["GosecVersion"]
			_, hasIssues := obj["Issues"]
			if hasVersion && hasIssues {
				return 1.0
			}
			return 0
		},
	})
	Register(ConverterFingerprint{
		ID: "junit-to-hdf", Label: "JUnit",
		Direction: DirectionIngest, InputFamily: FamilyXML, OutputType: OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			if containsRootElement(s, "testsuites") || containsRootElement(s, "testsuite") {
				return 1.0
			}
			return 0
		},
	})
	Register(ConverterFingerprint{
		ID: "xccdf-results-to-hdf", Label: "XCCDF",
		Direction: DirectionIngest, InputFamily: FamilyXML, OutputType: OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			if containsRootElement(s, "Benchmark") {
				return 1.0
			}
			return 0
		},
	})
}

// simple root element check for test fingerprints
func containsRootElement(xml, element string) bool {
	return len(xml) > 0 && (indexOf(xml, "<"+element+" ") >= 0 || indexOf(xml, "<"+element+">") >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func TestDetectFamily(t *testing.T) {
	assert.Equal(t, FamilyJSON, DetectFamily([]byte(`{"key":"val"}`)))
	assert.Equal(t, FamilyJSON, DetectFamily([]byte(`[1,2,3]`)))
	assert.Equal(t, FamilyXML, DetectFamily([]byte(`<?xml version="1.0"?><root/>`)))
	assert.Equal(t, FamilyXML, DetectFamily([]byte(`<root/>`)))
	assert.Equal(t, FamilyText, DetectFamily([]byte(`hello world`)))
	assert.Equal(t, FamilyText, DetectFamily([]byte(`  hello`)))
	assert.Equal(t, InputFamily(""), DetectFamily([]byte{}))
	assert.Equal(t, InputFamily(""), DetectFamily(nil))
}

func TestDetectConverter(t *testing.T) {
	t.Run("returns nil when no fingerprints", func(t *testing.T) {
		ResetRegistry()
		assert.Nil(t, DetectConverter([]byte(sarifInput)))
	})

	t.Run("detects SARIF", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints()
		result := DetectConverter([]byte(sarifInput))
		require.NotNil(t, result)
		assert.Equal(t, "sarif-to-hdf", result.Fingerprint.ID)
		assert.Equal(t, 0.9, result.Confidence)
	})

	t.Run("detects GoSec (not confused with SARIF)", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints()
		result := DetectConverter([]byte(gosecInput))
		require.NotNil(t, result)
		assert.Equal(t, "gosec-to-hdf", result.Fingerprint.ID)
		assert.Equal(t, 1.0, result.Confidence)
	})

	t.Run("detects JUnit XML", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints()
		result := DetectConverter([]byte(junitInput))
		require.NotNil(t, result)
		assert.Equal(t, "junit-to-hdf", result.Fingerprint.ID)
	})

	t.Run("detects XCCDF XML", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints()
		result := DetectConverter([]byte(xccdfInput))
		require.NotNil(t, result)
		assert.Equal(t, "xccdf-results-to-hdf", result.Fingerprint.ID)
	})

	t.Run("returns nil for garbage", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints()
		assert.Nil(t, DetectConverter([]byte("not valid anything")))
	})

	t.Run("returns nil for empty", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints()
		assert.Nil(t, DetectConverter([]byte{}))
	})

	t.Run("returns nil for invalid JSON", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints()
		assert.Nil(t, DetectConverter([]byte("{broken")))
	})

	t.Run("does not match JSON fingerprint against XML", func(t *testing.T) {
		ResetRegistry()
		Register(ConverterFingerprint{
			ID: "json-only", Label: "J", Direction: DirectionIngest,
			InputFamily: FamilyJSON, OutputType: OutputResults,
			Fingerprint: func(input any) float64 { return 1.0 },
		})
		assert.Nil(t, DetectConverter([]byte(junitInput)))
	})

	t.Run("skips export fingerprints", func(t *testing.T) {
		ResetRegistry()
		Register(ConverterFingerprint{
			ID: "hdf-to-csv", Label: "Export", Direction: DirectionExport,
			InputFamily: FamilyJSON, OutputType: OutputRaw,
			Fingerprint: func(input any) float64 { return 1.0 },
		})
		assert.Nil(t, DetectConverter([]byte(sarifInput)))
	})
}

func TestDetectConverter_BOM(t *testing.T) {
	withBOM := func(s string) []byte {
		return append(append([]byte{}, utf8BOM...), []byte(s)...)
	}

	t.Run("detects BOM-prefixed JSON", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints()
		result := DetectConverter(withBOM(gosecInput))
		require.NotNil(t, result)
		assert.Equal(t, "gosec-to-hdf", result.Fingerprint.ID)
	})

	t.Run("detects BOM-prefixed XML", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints()
		result := DetectConverter(withBOM(junitInput))
		require.NotNil(t, result)
		assert.Equal(t, "junit-to-hdf", result.Fingerprint.ID)
	})

	t.Run("detects BOM-prefixed NDJSON", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints()
		result := DetectConverter(withBOM(gosecInput + "\n" + gosecInput))
		require.NotNil(t, result)
		assert.Equal(t, "gosec-to-hdf", result.Fingerprint.ID)
	})
}

func TestDetectConverterAll(t *testing.T) {
	t.Run("returns sorted by confidence", func(t *testing.T) {
		ResetRegistry()
		Register(ConverterFingerprint{
			ID: "snyk-to-hdf", Label: "Snyk", Direction: DirectionIngest,
			InputFamily: FamilyJSON, OutputType: OutputResults,
			Fingerprint: func(input any) float64 {
				obj, ok := input.(map[string]any)
				if !ok {
					return 0
				}
				if _, has := obj["vulnerabilities"]; has {
					return 0.5
				}
				return 0
			},
		})
		Register(ConverterFingerprint{
			ID: "gitlab-to-hdf", Label: "GitLab", Direction: DirectionIngest,
			InputFamily: FamilyJSON, OutputType: OutputResults,
			Fingerprint: func(input any) float64 {
				obj, ok := input.(map[string]any)
				if !ok {
					return 0
				}
				if _, has := obj["vulnerabilities"]; has {
					return 0.4
				}
				return 0
			},
		})

		ambiguous := []byte(`{"vulnerabilities":[{"id":"CVE-2024-1234"}]}`)
		results := DetectConverterAll(ambiguous)
		require.Len(t, results, 2)
		assert.Equal(t, "snyk-to-hdf", results[0].Fingerprint.ID)
		assert.Equal(t, 0.5, results[0].Confidence)
		assert.Equal(t, "gitlab-to-hdf", results[1].Fingerprint.ID)
		assert.Equal(t, 0.4, results[1].Confidence)
	})
}

func TestDetectConverterAll_NDJSON(t *testing.T) {
	t.Run("detects NDJSON (one object per line)", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints()
		ndjson := []byte(gosecInput + "\n" + gosecInput + "\n")
		results := DetectConverterAll(ndjson)
		require.Len(t, results, 1)
		assert.Equal(t, "gosec-to-hdf", results[0].Fingerprint.ID)
		assert.Equal(t, 1.0, results[0].Confidence)
	})

	t.Run("skips leading blank lines", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints()
		ndjson := []byte("\n  \n" + gosecInput + "\n" + gosecInput)
		results := DetectConverterAll(ndjson)
		require.Len(t, results, 1)
		assert.Equal(t, "gosec-to-hdf", results[0].Fingerprint.ID)
	})

	t.Run("returns nil when the first line is malformed", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints()
		assert.Nil(t, DetectConverterAll([]byte("{broken\n{also broken")))
	})

	t.Run("single object with trailing newline still uses whole-input parse", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints()
		results := DetectConverterAll([]byte(gosecInput + "\n"))
		require.Len(t, results, 1)
		assert.Equal(t, "gosec-to-hdf", results[0].Fingerprint.ID)
	})
}

func TestDetectConverterAll_VersionDetection(t *testing.T) {
	t.Run("populates Version from DetectVersion", func(t *testing.T) {
		ResetRegistry()
		Register(ConverterFingerprint{
			ID: "sarif-to-hdf", Label: "SARIF",
			Direction: DirectionIngest, InputFamily: FamilyJSON, OutputType: OutputResults,
			Fingerprint: func(input any) float64 {
				obj, ok := input.(map[string]any)
				if !ok {
					return 0
				}
				if _, hasVer := obj["version"]; hasVer {
					if _, hasRuns := obj["runs"]; hasRuns {
						return 0.9
					}
				}
				return 0
			},
			DetectVersion: func(input any) string {
				obj, ok := input.(map[string]any)
				if !ok {
					return ""
				}
				if v, ok := obj["version"].(string); ok {
					return v
				}
				return ""
			},
		})

		results := DetectConverterAll([]byte(sarifInput))
		require.Len(t, results, 1)
		assert.Equal(t, "sarif-to-hdf", results[0].Fingerprint.ID)
		assert.Equal(t, "2.1.0", results[0].Version)
	})

	t.Run("Version empty when DetectVersion is nil", func(t *testing.T) {
		ResetRegistry()
		registerTestFingerprints() // these have nil DetectVersion
		results := DetectConverterAll([]byte(sarifInput))
		require.NotEmpty(t, results)
		assert.Equal(t, "", results[0].Version)
	})

	t.Run("Version empty when DetectVersion panics", func(t *testing.T) {
		ResetRegistry()
		Register(ConverterFingerprint{
			ID: "panic-ver", Label: "PanicVer",
			Direction: DirectionIngest, InputFamily: FamilyJSON, OutputType: OutputResults,
			Fingerprint: func(input any) float64 { return 0.9 },
			DetectVersion: func(input any) string {
				panic("version detection failed")
			},
		})
		results := DetectConverterAll([]byte(`{"key":"val"}`))
		require.Len(t, results, 1)
		assert.Equal(t, "", results[0].Version)
	})
}

func TestDetectConverter_VersionPassthrough(t *testing.T) {
	ResetRegistry()
	Register(ConverterFingerprint{
		ID: "sarif-to-hdf", Label: "SARIF",
		Direction: DirectionIngest, InputFamily: FamilyJSON, OutputType: OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			if _, hasVer := obj["version"]; hasVer {
				if _, hasRuns := obj["runs"]; hasRuns {
					return 0.9
				}
			}
			return 0
		},
		DetectVersion: func(input any) string {
			obj, ok := input.(map[string]any)
			if !ok {
				return ""
			}
			if v, ok := obj["version"].(string); ok {
				return v
			}
			return ""
		},
	})

	result := DetectConverter([]byte(sarifInput))
	require.NotNil(t, result)
	assert.Equal(t, "2.1.0", result.Version)
}
