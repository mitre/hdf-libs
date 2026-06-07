package hdfparsers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseResults_Valid(t *testing.T) {
	t.Run("should parse minimal valid HDF results", func(t *testing.T) {
		validJSON := []byte(`{
			"baselines": [{
				"name": "Test Baseline",
				"integrity": { "algorithm": "sha256", "checksum": "abc123" },
				"requirements": [{
					"id": "REQ-001",
					"descriptions": [{ "label": "default", "data": "Test description" }],
					"impact": 0.5,
					"tags": {},
					"results": [{
						"status": "passed",
						"codeDesc": "Test",
						"startTime": "2025-01-01T00:00:00Z"
					}]
				}]
			}],
			"components": [],
			"statistics": {}
		}`)

		result := ParseResults(validJSON)

		assert.True(t, result.Success)
		assert.Empty(t, result.Error)
		assert.NotNil(t, result.Data)
		assert.Equal(t, 1, len(result.Data.Baselines))
		assert.Equal(t, "Test Baseline", result.Data.Baselines[0].Name)
	})

	t.Run("should parse complex HDF results with multiple baselines", func(t *testing.T) {
		complexJSON := []byte(`{
			"baselines": [
				{
					"name": "Baseline 1",
					"integrity": { "algorithm": "sha256", "checksum": "hash1" },
					"requirements": [{
						"id": "REQ-001",
						"descriptions": [{ "label": "default", "data": "Desc 1" }],
						"impact": 0.7,
						"tags": { "nist": ["AC-1"] },
						"results": [{
							"status": "failed",
							"codeDesc": "Check 1",
							"startTime": "2025-01-01T00:00:00Z",
							"message": "Failed check"
						}]
					}]
				},
				{
					"name": "Baseline 2",
					"integrity": { "algorithm": "sha512", "checksum": "hash2" },
					"requirements": [{
						"id": "REQ-002",
						"descriptions": [{ "label": "default", "data": "Desc 2" }],
						"impact": 0.3,
						"tags": {},
						"results": [{
							"status": "passed",
							"codeDesc": "Check 2",
							"startTime": "2025-01-02T00:00:00Z"
						}]
					}]
				}
			],
			"components": [],
			"statistics": {}
		}`)

		result := ParseResults(complexJSON)

		assert.True(t, result.Success)
		assert.NotNil(t, result.Data)
		assert.Equal(t, 2, len(result.Data.Baselines))
	})
}

func TestParseResults_Invalid(t *testing.T) {
	t.Run("should reject invalid JSON syntax", func(t *testing.T) {
		invalidJSON := []byte(`{ "baselines": [invalid json }`)

		result := ParseResults(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
		assert.Regexp(t, "(?i)(JSON|invalid|character)", result.Error)
		assert.Nil(t, result.Data)
	})

	t.Run("should reject results missing baselines field", func(t *testing.T) {
		invalidJSON := []byte(`{
			"components": [],
			"statistics": {}
		}`)

		result := ParseResults(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
		assert.Contains(t, result.Error, "baselines")
	})

	t.Run("should reject results with invalid baseline structure", func(t *testing.T) {
		invalidJSON := []byte(`{
			"baselines": [{
				"integrity": { "algorithm": "sha256", "checksum": "test" },
				"requirements": []
			}],
			"components": [],
			"statistics": {}
		}`)

		result := ParseResults(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})

	t.Run("should reject results with invalid requirement", func(t *testing.T) {
		invalidJSON := []byte(`{
			"baselines": [{
				"name": "Test",
				"integrity": { "algorithm": "sha256", "checksum": "test" },
				"requirements": [{
					"id": "REQ-001",
					"impact": 0.5,
					"tags": {},
					"results": []
				}]
			}],
			"components": [],
			"statistics": {}
		}`)

		result := ParseResults(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})

	t.Run("should reject empty input", func(t *testing.T) {
		result := ParseResults([]byte(""))

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})

	t.Run("should reject whitespace-only input", func(t *testing.T) {
		result := ParseResults([]byte("   \n\t  "))

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})
}

func TestParseBaseline_Valid(t *testing.T) {
	t.Run("should parse minimal valid HDF baseline", func(t *testing.T) {
		validJSON := []byte(`{
			"name": "Security Baseline",
			"title": "Test Baseline",
			"version": "1.0.0",
			"integrity": { "algorithm": "sha256", "checksum": "def456" },
			"requirements": [{
				"id": "REQ-001",
				"title": "Access Control",
				"descriptions": [{ "label": "default", "data": "Requirement description" }],
				"impact": 0.7,
				"tags": { "nist": ["AC-1", "AC-2"] }
			}]
		}`)

		result := ParseBaseline(validJSON)

		assert.True(t, result.Success)
		assert.NotNil(t, result.Data)
		assert.Equal(t, "Security Baseline", result.Data.Name)
		assert.Equal(t, 1, len(result.Data.Requirements))
	})

	t.Run("should parse baseline with multiple requirements", func(t *testing.T) {
		validJSON := []byte(`{
			"name": "Multi-Req Baseline",
			"version": "2.0.0",
			"integrity": { "algorithm": "sha512", "checksum": "hash" },
			"requirements": [
				{
					"id": "REQ-001",
					"title": "Requirement 1",
					"descriptions": [{ "label": "default", "data": "Desc 1" }],
					"impact": 0.5,
					"tags": {}
				},
				{
					"id": "REQ-002",
					"title": "Requirement 2",
					"descriptions": [{ "label": "default", "data": "Desc 2" }],
					"impact": 0.8,
					"tags": { "nist": ["AU-1"] }
				}
			]
		}`)

		result := ParseBaseline(validJSON)

		assert.True(t, result.Success)
		assert.Equal(t, 2, len(result.Data.Requirements))
	})
}

func TestParseBaseline_Invalid(t *testing.T) {
	t.Run("should reject baseline missing name", func(t *testing.T) {
		invalidJSON := []byte(`{
			"version": "1.0.0",
			"integrity": { "algorithm": "sha256", "checksum": "test" },
			"requirements": []
		}`)

		result := ParseBaseline(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})

	t.Run("should reject baseline with empty requirements array", func(t *testing.T) {
		invalidJSON := []byte(`{
			"name": "Test Baseline",
			"integrity": { "algorithm": "sha256", "checksum": "test" },
			"requirements": []
		}`)

		result := ParseBaseline(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})
}

func TestParse_AutoDetection(t *testing.T) {
	t.Run("should auto-detect and parse HDF Results", func(t *testing.T) {
		resultsJSON := []byte(`{
			"baselines": [{
				"name": "Test",
				"integrity": { "algorithm": "sha256", "checksum": "test" },
				"requirements": [{
					"id": "REQ-001",
					"descriptions": [{ "label": "default", "data": "Test" }],
					"impact": 0.5,
					"tags": {},
					"results": [{ "status": "passed", "codeDesc": "OK", "startTime": "2025-01-01T00:00:00Z" }]
				}]
			}],
			"components": [],
			"statistics": {}
		}`)

		result := Parse(resultsJSON)

		assert.True(t, result.Success)
		assert.Equal(t, "results", result.Type)
		assert.NotNil(t, result.Data)
	})

	t.Run("should auto-detect and parse HDF Baseline", func(t *testing.T) {
		baselineJSON := []byte(`{
			"name": "Test Baseline",
			"version": "1.0.0",
			"integrity": { "algorithm": "sha256", "checksum": "test" },
			"requirements": [{
				"id": "REQ-001",
				"title": "Test",
				"descriptions": [{ "label": "default", "data": "Test" }],
				"impact": 0.5,
				"tags": {}
			}]
		}`)

		result := Parse(baselineJSON)

		assert.True(t, result.Success)
		assert.Equal(t, "baseline", result.Type)
		assert.NotNil(t, result.Data)
	})

	t.Run("should return error for ambiguous document", func(t *testing.T) {
		ambiguousJSON := []byte(`{
			"unknown": "field"
		}`)

		result := Parse(ambiguousJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})

	t.Run("should return error for invalid document", func(t *testing.T) {
		invalidJSON := []byte(`{ invalid }`)

		result := Parse(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})
}

func TestErrorMessages(t *testing.T) {
	t.Run("should provide helpful error message for schema validation failure", func(t *testing.T) {
		invalidJSON := []byte(`{
			"baselines": [{
				"name": "Test"
			}],
			"components": [],
			"statistics": {}
		}`)

		result := ParseResults(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})

	t.Run("should provide helpful error for JSON parse failure", func(t *testing.T) {
		result := ParseResults([]byte(`{ not valid json`))

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
		assert.Regexp(t, "(?i)(JSON|parse|syntax|invalid|character)", result.Error)
	})
}

// --- NormalizeTimestamps ---

func TestNormalizeTimestamps(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"InSpec-style no-tz timestamp gets Z appended",
			`{"startTime":"2026-03-25T22:56:27.736808"}`,
			`{"startTime":"2026-03-25T22:56:27.736808Z"}`,
		},
		{
			"already-RFC3339 with Z is unchanged",
			`{"startTime":"2026-03-25T22:56:27Z"}`,
			`{"startTime":"2026-03-25T22:56:27Z"}`,
		},
		{
			"already-RFC3339 with +HH:MM offset is unchanged",
			`{"startTime":"2026-03-25T22:56:27+05:30"}`,
			`{"startTime":"2026-03-25T22:56:27+05:30"}`,
		},
		{
			"already-RFC3339 with -HH:MM offset is unchanged",
			`{"startTime":"2026-03-25T22:56:27-05:00"}`,
			`{"startTime":"2026-03-25T22:56:27-05:00"}`,
		},
		{
			"no fractional seconds also gets Z",
			`{"startTime":"2026-03-25T22:56:27"}`,
			`{"startTime":"2026-03-25T22:56:27Z"}`,
		},
		{
			"multiple timestamps in one doc all get normalized",
			`{"timestamp":"2026-03-25T22:56:27","baselines":[{"requirements":[{"results":[{"startTime":"2026-03-25T22:56:28.5"}]}]}]}`,
			`{"timestamp":"2026-03-25T22:56:27Z","baselines":[{"requirements":[{"results":[{"startTime":"2026-03-25T22:56:28.5Z"}]}]}]}`,
		},
		{
			"timestamp-shaped substring inside prose is not touched",
			`{"codeDesc":"job started at 2026-03-25T22:56:27 and finished"}`,
			`{"codeDesc":"job started at 2026-03-25T22:56:27 and finished"}`,
		},
		{
			"empty input is unchanged",
			``,
			``,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeTimestamps([]byte(tc.in))
			assert.Equal(t, tc.want, string(got))
		})
	}
}

func TestParseResults_AcceptsInSpecNoTzTimestamps(t *testing.T) {
	input := []byte(`{
		"timestamp": "2026-03-25T22:56:27.736808",
		"generator": {"name": "inspec", "version": "5.0.0"},
		"baselines": [{
			"name": "test",
			"resultsChecksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"},
			"requirements": [{
				"id": "x",
				"impact": 0.5,
				"tags": {},
				"descriptions": [{"label": "default", "data": "x"}],
				"results": [{"status": "passed", "codeDesc": "x", "startTime": "2026-03-25T22:56:27.736808"}]
			}]
		}]
	}`)
	result := ParseResults(input)
	assert.True(t, result.Success, "should accept no-tz timestamps; got error: %s", result.Error)
	assert.NotNil(t, result.Data)
	require := func(b bool, msg string) {
		if !b {
			t.Fatalf("%s", msg)
		}
	}
	require(result.Data != nil, "result.Data is nil")
	require(result.Data.Timestamp != nil, "Timestamp pointer is nil after parse")
	assert.Equal(t, "2026-03-25T22:56:27.736808Z", result.Data.Timestamp.Format("2006-01-02T15:04:05.999999Z07:00"))
}
