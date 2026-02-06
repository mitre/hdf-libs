package hdftoxml

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertHDFToXML(t *testing.T) {
	t.Run("should convert minimal HDF to XML", func(t *testing.T) {
		input, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "minimal.json"))
		require.NoError(t, err)

		expected, err := os.ReadFile(filepath.Join("..", "fixtures", "expected", "minimal.xml"))
		require.NoError(t, err)

		result, err := ConvertHDFToXML(input)
		require.NoError(t, err)

		// Normalize whitespace for comparison
		normalizeWhitespace := func(s string) string {
			s = strings.TrimSpace(s)
			s = strings.ReplaceAll(s, "\r\n", "\n")
			return s
		}

		// Skip XML header for comparison
		resultStr := string(result)
		if strings.HasPrefix(resultStr, "<?xml") {
			lines := strings.Split(resultStr, "\n")
			if len(lines) > 1 {
				resultStr = strings.Join(lines[1:], "\n")
			}
		}

		assert.Equal(t, normalizeWhitespace(string(expected)), normalizeWhitespace(resultStr))
	})

	t.Run("should handle empty baselines array", func(t *testing.T) {
		input := []byte(`{
			"baselines": [],
			"targets": [],
			"statistics": { "duration": 0 }
		}`)

		result, err := ConvertHDFToXML(input)
		require.NoError(t, err)

		resultStr := string(result)
		assert.Contains(t, resultStr, "<HdfResults>")
		assert.Contains(t, resultStr, "<baselines>")
		assert.Contains(t, resultStr, "</HdfResults>")
	})

	t.Run("should handle baselines with no requirements", func(t *testing.T) {
		input := []byte(`{
			"baselines": [{
				"name": "Empty Baseline",
				"version": "1.0.0",
				"title": "Test",
				"checksum": { "algorithm": "sha256", "value": "abc" },
				"requirements": []
			}],
			"targets": [],
			"statistics": { "duration": 0 }
		}`)

		result, err := ConvertHDFToXML(input)
		require.NoError(t, err)

		resultStr := string(result)
		assert.Contains(t, resultStr, "<baseline>")
		assert.Contains(t, resultStr, "<name>Empty Baseline</name>")
	})

	t.Run("should throw error for invalid JSON", func(t *testing.T) {
		_, err := ConvertHDFToXML([]byte("not json"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid HDF JSON")
	})

	t.Run("should throw error for missing baselines field", func(t *testing.T) {
		_, err := ConvertHDFToXML([]byte(`{"foo": "bar"}`))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid HDF structure: missing baselines field")
	})

	t.Run("should handle multiple baselines and targets", func(t *testing.T) {
		input := []byte(`{
			"baselines": [{
				"name": "Baseline 1",
				"version": "1.0.0",
				"checksum": { "algorithm": "sha256", "value": "abc" },
				"requirements": [{
					"id": "REQ-001",
					"title": "Test Requirement",
					"descriptions": [{ "label": "default", "data": "Test description" }],
					"impact": 0.5,
					"tags": {},
					"results": [{ "status": "passed", "codeDesc": "Test", "startTime": "2025-01-01T00:00:00Z" }]
				}]
			}],
			"targets": [{ "name": "Target 1", "type": "host" }],
			"statistics": { "duration": 10.5 }
		}`)

		result, err := ConvertHDFToXML(input)
		require.NoError(t, err)

		resultStr := string(result)
		assert.Contains(t, resultStr, "<name>Baseline 1</name>")
		assert.Contains(t, resultStr, "<id>REQ-001</id>")
		assert.Contains(t, resultStr, "<title>Test Requirement</title>")
		assert.Contains(t, resultStr, "<target>")
		assert.Contains(t, resultStr, "<name>Target 1</name>")
		assert.Contains(t, resultStr, "<type>host</type>")
	})

	t.Run("should escape special characters in XML", func(t *testing.T) {
		input := []byte(`{
			"baselines": [{
				"name": "Test & < > \" '",
				"checksum": { "algorithm": "sha256", "value": "abc" },
				"requirements": [{
					"id": "REQ-001",
					"title": "Description with <tags> & special chars",
					"descriptions": [{ "label": "default", "data": "Data" }],
					"impact": 0.5,
					"tags": {},
					"results": [{ "status": "passed", "codeDesc": "Test", "startTime": "2025-01-01T00:00:00Z" }]
				}]
			}],
			"statistics": {}
		}`)

		result, err := ConvertHDFToXML(input)
		require.NoError(t, err)

		resultStr := string(result)
		// XML should escape special characters
		assert.Contains(t, resultStr, "&amp;")
		assert.Contains(t, resultStr, "&lt;")
		assert.Contains(t, resultStr, "&gt;")
	})

	t.Run("should produce valid XML", func(t *testing.T) {
		input := []byte(`{
			"baselines": [{
				"name": "Test Baseline",
				"checksum": { "algorithm": "sha256", "value": "abc" },
				"requirements": [{
					"id": "REQ-001",
					"descriptions": [{ "label": "default", "data": "Test" }],
					"impact": 0.5,
					"tags": {},
					"results": [{ "status": "passed", "codeDesc": "Test", "startTime": "2025-01-01T00:00:00Z" }]
				}]
			}],
			"statistics": {}
		}`)

		result, err := ConvertHDFToXML(input)
		require.NoError(t, err)

		// Validate that output is valid XML by parsing it
		var parsed XMLHDFResults
		err = xml.Unmarshal(result, &parsed)
		assert.NoError(t, err)
	})
}
