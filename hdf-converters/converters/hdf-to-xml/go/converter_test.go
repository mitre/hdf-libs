package hdftoxml

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real InSpec HDF carries zone-less timestamps ("2026-03-25T22:56:27.736808").
// They must be ingested (the schema's time.Time fields reject them raw) and
// emitted as canonical trimmed-UTC RFC3339, identical to the TypeScript output.
func TestConvertHDFToXMLBareTimestamps(t *testing.T) {
	result, err := ConvertHDFToXML(fixtures.Results.InspecMultilayered)
	require.NoError(t, err)

	out := string(result)
	assert.Contains(t, out, "<startTime>2026-03-25T22:56:27.736Z</startTime>")
	assert.NotContains(t, out, "2026-03-25T22:56:27.736808")
}

func TestConvertHDFToXML(t *testing.T) {
	t.Run("should convert minimal HDF to XML", func(t *testing.T) {
		input := fixtures.Results.Minimal

		expected, err := os.ReadFile(filepath.Join("..", "fixtures", "expected", "minimal.xml"))
		require.NoError(t, err)

		result, err := ConvertHDFToXML(input)
		require.NoError(t, err)

		// Same shared normalization the TS test uses — previously each language
		// normalized this golden its own way, so they were not comparing like for like.
		assert.Equal(t, shared.NormalizeXMLForGolden(string(expected)), shared.NormalizeXMLForGolden(string(result)))
	})

	t.Run("should losslessly serialize all Requirement_Core / baseline / component fields", func(t *testing.T) {
		input, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "full.json"))
		require.NoError(t, err)
		expected, err := os.ReadFile(filepath.Join("..", "fixtures", "expected", "full.xml"))
		require.NoError(t, err)

		result, err := ConvertHDFToXML(input)
		require.NoError(t, err)

		// Golden compare under the shared normalization — this is the TS/Go
		// parity assertion (both languages normalize the same golden identically).
		assert.Equal(t, shared.NormalizeXMLForGolden(string(expected)), shared.NormalizeXMLForGolden(string(result)))

		// Spot-check the fields that were previously dropped.
		for _, el := range []string{"<code>", "<sourceLocation>", "<controlType>", "<verificationMethod>", "<applicability>", "<refs>", "<summary>", "<resultsChecksum>", "<originalChecksum>", "<componentId>", "<gtitle>", "<generator>"} {
			assert.Contains(t, string(result), el, "missing element %s", el)
		}
	})

	t.Run("should handle empty baselines array", func(t *testing.T) {
		input := []byte(`{
			"baselines": [],
			"components": [],
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
			"components": [],
			"statistics": { "duration": 0 }
		}`)

		result, err := ConvertHDFToXML(input)
		require.NoError(t, err)

		resultStr := string(result)
		assert.Contains(t, resultStr, "<baseline>")
		assert.Contains(t, resultStr, "<name>Empty Baseline</name>")
	})

	t.Run("emits host identity fields (hostname, fqdn, domain) in a stable order", func(t *testing.T) {
		input := []byte(`{
			"baselines": [{ "name": "B", "version": "1.0.0", "title": "T", "checksum": { "algorithm": "sha256", "value": "abc" }, "requirements": [] }],
			"components": [{ "type": "host", "name": "web01", "hostname": "web01", "fqdn": "web01.prod.example.com", "domain": "CORP", "ipAddress": "10.0.1.5" }],
			"statistics": { "duration": 0 }
		}`)
		result, err := ConvertHDFToXML(input)
		require.NoError(t, err)
		out := string(result)
		assert.Contains(t, out, "<hostname>web01</hostname>")
		assert.Contains(t, out, "<fqdn>web01.prod.example.com</fqdn>")
		assert.Contains(t, out, "<domain>CORP</domain>")
		// hostname before fqdn before domain before ipAddress (parity with TS).
		assert.True(t, strings.Index(out, "<hostname>") < strings.Index(out, "<fqdn>"))
		assert.True(t, strings.Index(out, "<fqdn>") < strings.Index(out, "<domain>"))
		assert.True(t, strings.Index(out, "<domain>") < strings.Index(out, "<ipAddress>"))
	})

	t.Run("should throw error for invalid JSON", func(t *testing.T) {
		_, err := ConvertHDFToXML([]byte("not json"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid HDF JSON")
	})

	t.Run("should throw error for missing baselines field", func(t *testing.T) {
		_, err := ConvertHDFToXML([]byte(`{"foo": "bar"}`))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid HDF structure: missing baselines field")
	})

	t.Run("should handle multiple baselines and components", func(t *testing.T) {
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
			"components": [{ "name": "Target 1", "type": "host" }],
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

	t.Run("should handle nil statistics without panic", func(t *testing.T) {
		// Regression: hdf.Statistics is *Statistics. If the input JSON omits
		// the statistics block entirely, Statistics is nil and accessing
		// Statistics.Duration caused a nil pointer dereference.
		input := []byte(`{
			"baselines": [{
				"name": "No Stats Baseline",
				"checksum": { "algorithm": "sha256", "value": "abc" },
				"requirements": []
			}],
			"components": []
		}`)

		result, err := ConvertHDFToXML(input)
		require.NoError(t, err)

		resultStr := string(result)
		assert.Contains(t, resultStr, "<HdfResults>")
		assert.Contains(t, resultStr, "<name>No Stats Baseline</name>")
		// statistics element should be absent
		assert.NotContains(t, resultStr, "<statistics>")
	})

	t.Run("should handle empty statistics object without panic", func(t *testing.T) {
		// statistics present but Duration is nil (omitted)
		input := []byte(`{
			"baselines": [{
				"name": "Empty Stats Baseline",
				"checksum": { "algorithm": "sha256", "value": "abc" },
				"requirements": []
			}],
			"statistics": {}
		}`)

		result, err := ConvertHDFToXML(input)
		require.NoError(t, err)

		resultStr := string(result)
		assert.Contains(t, resultStr, "<HdfResults>")
		// No duration means no statistics element in output
		assert.NotContains(t, resultStr, "<statistics>")
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
