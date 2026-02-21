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

	t.Run("returns unknown for XML input", func(t *testing.T) {
		input := `<?xml version="1.0"?><testsuites><testsuite/></testsuites>`
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
}
