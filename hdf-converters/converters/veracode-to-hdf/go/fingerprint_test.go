package veracode

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVeracodeFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("veracode-to-hdf")
		require.NotNil(t, fp, "veracode-to-hdf should be registered via init()")
		assert.Equal(t, "Veracode", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyXML, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects detailedreport root at confidence 1.0", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<detailedreport xmlns="https://www.veracode.com/schema/reports/export/1.0" report_format_version="1.5.0">
  <severity level="5"><category categoryname="SQL Injection"/></severity>
</detailedreport>`
		fp := registry.GetFingerprint("veracode-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects namespaced detailedreport at confidence 1.0", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<ns:detailedreport xmlns:ns="https://www.veracode.com/schema/reports/export/1.0">
  <ns:severity level="5"/>
</ns:detailedreport>`
		fp := registry.GetFingerprint("veracode-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("does not match summaryreport", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<summaryreport xmlns="https://www.veracode.com/schema/reports/export/1.0">
  <severity level="5"/>
</summaryreport>`
		fp := registry.GetFingerprint("veracode-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match different XML format", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<testsuites>
  <testsuite name="Suite1"><testcase name="test1"/></testsuite>
</testsuites>`
		fp := registry.GetFingerprint("veracode-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("veracode-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match non-string input", func(t *testing.T) {
		fp := registry.GetFingerprint("veracode-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(map[string]any{"detailedreport": true}))
	})
}
