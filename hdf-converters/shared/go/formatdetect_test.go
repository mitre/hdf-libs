package testing

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectFormat(t *testing.T) {
	t.Run("detects SARIF with version and runs", func(t *testing.T) {
		input := `{"version": "2.1.0", "runs": [{"tool": {}, "results": []}]}`
		assert.Equal(t, FormatSARIF, DetectFormat([]byte(input)))
	})

	t.Run("detects SARIF with schema field", func(t *testing.T) {
		input := `{"$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json", "version": "2.1.0", "runs": []}`
		assert.Equal(t, FormatSARIF, DetectFormat([]byte(input)))
	})

	t.Run("returns unknown for gosec native JSON", func(t *testing.T) {
		input := `{"GosecVersion": "2.18.2", "Issues": [], "Stats": {"files": 1}}`
		assert.Equal(t, FormatUnknown, DetectFormat([]byte(input)))
	})

	t.Run("returns unknown for empty input", func(t *testing.T) {
		assert.Equal(t, FormatUnknown, DetectFormat([]byte("")))
	})

	t.Run("returns unknown for nil input", func(t *testing.T) {
		assert.Equal(t, FormatUnknown, DetectFormat(nil))
	})

	t.Run("detects JUnit XML with testsuites root", func(t *testing.T) {
		input := `<?xml version="1.0"?><testsuites><testsuite name="test"/></testsuites>`
		assert.Equal(t, FormatJUnit, DetectFormat([]byte(input)))
	})

	t.Run("detects JUnit XML with testsuite root", func(t *testing.T) {
		input := `<testsuite name="test" tests="1"><testcase name="t1"/></testsuite>`
		assert.Equal(t, FormatJUnit, DetectFormat([]byte(input)))
	})

	t.Run("detects JUnit XML with whitespace before", func(t *testing.T) {
		input := `  <?xml version="1.0"?><testsuites/>`
		assert.Equal(t, FormatJUnit, DetectFormat([]byte(input)))
	})

	t.Run("returns unknown for non-JUnit XML", func(t *testing.T) {
		input := `<?xml version="1.0"?><root><item/></root>`
		assert.Equal(t, FormatUnknown, DetectFormat([]byte(input)))
	})

	t.Run("returns unknown for invalid JSON", func(t *testing.T) {
		assert.Equal(t, FormatUnknown, DetectFormat([]byte("not json")))
	})

	t.Run("returns unknown for JSON array", func(t *testing.T) {
		assert.Equal(t, FormatUnknown, DetectFormat([]byte(`[1, 2, 3]`)))
	})

	t.Run("returns unknown when version is number not string", func(t *testing.T) {
		input := `{"version": 2, "runs": []}`
		assert.Equal(t, FormatUnknown, DetectFormat([]byte(input)))
	})

	t.Run("returns unknown when runs is object not array", func(t *testing.T) {
		input := `{"version": "2.1.0", "runs": {}}`
		assert.Equal(t, FormatUnknown, DetectFormat([]byte(input)))
	})

	t.Run("returns unknown when version missing", func(t *testing.T) {
		input := `{"runs": []}`
		assert.Equal(t, FormatUnknown, DetectFormat([]byte(input)))
	})

	t.Run("returns unknown when runs missing", func(t *testing.T) {
		input := `{"version": "2.1.0"}`
		assert.Equal(t, FormatUnknown, DetectFormat([]byte(input)))
	})

	t.Run("handles whitespace before JSON", func(t *testing.T) {
		input := `  {"version": "2.1.0", "runs": []}`
		assert.Equal(t, FormatSARIF, DetectFormat([]byte(input)))
	})

	t.Run("returns unknown for invalid XML", func(t *testing.T) {
		input := `<unclosed`
		assert.Equal(t, FormatUnknown, DetectFormat([]byte(input)))
	})

	t.Run("detects XCCDF Benchmark XML", func(t *testing.T) {
		input := `<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test"><status>incomplete</status></Benchmark>`
		assert.Equal(t, FormatXCCDF, DetectFormat([]byte(input)))
	})

	t.Run("detects ARF asset-report-collection XML", func(t *testing.T) {
		input := `<?xml version="1.0"?><asset-report-collection xmlns="http://scap.nist.gov/schema/asset-reporting-format/1.1"></asset-report-collection>`
		assert.Equal(t, FormatARF, DetectFormat([]byte(input)))
	})

	t.Run("detects ARF with namespace prefix", func(t *testing.T) {
		input := `<?xml version="1.0"?><arf:asset-report-collection xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1"></arf:asset-report-collection>`
		assert.Equal(t, FormatARF, DetectFormat([]byte(input)))
	})

	t.Run("detects XCCDF with namespace prefix", func(t *testing.T) {
		input := `<?xml version="1.0"?><xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="test"><xccdf:status>incomplete</xccdf:status></xccdf:Benchmark>`
		assert.Equal(t, FormatXCCDF, DetectFormat([]byte(input)))
	})
}
