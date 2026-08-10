package hdftoxml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
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

	t.Run("losslessly serializes the post-v3.2 fields the struct mirror dropped", func(t *testing.T) {
		input, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "full.json"))
		require.NoError(t, err)
		result, err := ConvertHDFToXML(input)
		require.NoError(t, err)
		// Collapse indentation (and decode escaped apostrophes) so the structural
		// multi-element assertions below are not defeated by pretty-printing.
		out := shared.NormalizeXMLForGolden(string(result))

		// Scalar arrays render as repeated unwrapped keys; object arrays keep the
		// wrapper + singular-child form.
		assert.Contains(t, out, "<tags><cci>CCI-000012</cci><gtitle>SRG-OS-000480-GPOS-00227</gtitle><nist>AC-2</nist><nist>AC-3</nist><severity>high</severity></tags>")

		// Requirement-level overrides, dispositions, and effective* fields.
		assert.Contains(t, out, "<statusOverrides><statusOverride><type>riskAdjustment</type>")
		assert.Contains(t, out, "<reason>Compensating control: host isolated on a management VLAN with no inbound internet exposure.</reason>")
		assert.Contains(t, out, "<impact><value>0.3</value></impact>")
		assert.Contains(t, out, "<appliedBy><identifier>jane.doe@example.gov</identifier>")
		assert.Contains(t, out, "<expiresAt>2099-12-31T00:00:00Z</expiresAt>")
		assert.Contains(t, out, "<justification>inline_mitigations_already_exist</justification>")
		assert.Contains(t, out, "<disposition>riskAdjustment</disposition>")
		assert.Contains(t, out, "<effectiveStatus>passed</effectiveStatus>")
		assert.Contains(t, out, "<effectiveImpact>0.3</effectiveImpact>")
		assert.Contains(t, out, "<severity>high</severity>")

		// Vulnerability enrichment. cvss is an object array (wrapped + singular
		// child); cwe is a scalar array (repeated, unwrapped key).
		assert.Contains(t, out, "<cvss><cvss><version>3.1</version>")
		assert.Contains(t, out, "<baseScore>9.8</baseScore>")
		assert.Contains(t, out, "<cwe>CWE-79</cwe><cwe>CWE-89</cwe>")
		assert.Contains(t, out, "<epss><score>0.00432</score><percentile>0.7421</percentile>")
		assert.Contains(t, out, "<kev><inKev>true</inKev>")
		assert.Contains(t, out, "<poams><poam><type>remediation</type>")
		assert.Contains(t, out, "<milestones><milestone><description>Vendor patch validated in staging</description>")
		assert.Contains(t, out, "<affectedPackages><affectedPackage><name>openssl</name>")

		// evidence is an unmapped object array -> wrapper + generic <item> child.
		assert.Contains(t, out, "<evidence><item><type>log</type>")

		// Result-level diagnostics. backtrace is a scalar (string) array ->
		// repeated, unwrapped key.
		assert.Contains(t, out, "<exception>RuntimeError</exception>")
		assert.Contains(t, out, "<backtrace>controls/SV-100001.rb:12:in `block'</backtrace>")
		assert.Contains(t, out, "<resource>sshd_config</resource>")
		assert.Contains(t, out, "<resourceId>/etc/ssh/sshd_config</resourceId>")

		// Baseline- and top-level fields.
		assert.Contains(t, out, "<maintainer>MITRE</maintainer>")
		assert.Contains(t, out, "<tool><name>InSpec</name><version>5.22.3</version><format>inspec-json</format></tool>")
		assert.Contains(t, out, "<signedBy>ci-signer@example.gov</signedBy>")
		assert.Contains(t, out, "<id>b1e7c0de-1a2b-4c3d-8e4f-5a6b7c8d9e0f</id>")
		assert.Contains(t, out, "<runner><name>inspec</name>")
		assert.Contains(t, out, "<macAddress>02:42:ac:11:00:02</macAddress>")
	})

	t.Run("scalar array renders unwrapped; unmapped object array falls back to <item>", func(t *testing.T) {
		input := []byte(`{
			"baselines": [{ "name": "B", "aliases": ["a", "b", "c"], "widgets": [{ "n": 1 }, { "n": 2 }], "requirements": [] }]
		}`)
		result, err := ConvertHDFToXML(input)
		require.NoError(t, err)
		out := shared.NormalizeXMLForGolden(string(result))
		// Scalar array -> repeated, unwrapped key.
		assert.Contains(t, out, "<aliases>a</aliases><aliases>b</aliases><aliases>c</aliases>")
		// Unmapped object array -> wrapper + <item> children.
		assert.Contains(t, out, "<widgets><item><n>1</n></item><item><n>2</n></item></widgets>")
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

	t.Run("should serialize an empty statistics object as an empty element", func(t *testing.T) {
		// The generic serializer is lossless: a present-but-empty statistics
		// object is rendered as an empty element rather than dropped.
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
		assert.Contains(t, resultStr, "<statistics></statistics>")
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

		// Validate the output is well-formed XML by decoding the whole token
		// stream (the serializer is generic now, so there is no mirror struct to
		// unmarshal into).
		dec := xml.NewDecoder(bytes.NewReader(result))
		for {
			_, terr := dec.Token()
			if errors.Is(terr, io.EOF) {
				break
			}
			require.NoError(t, terr)
		}
	})
}
