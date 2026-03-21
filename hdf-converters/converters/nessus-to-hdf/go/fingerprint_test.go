package nessus

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNessusFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("nessus-to-hdf")
		require.NotNil(t, fp, "nessus-to-hdf should be registered via init()")
		assert.Equal(t, "Nessus", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyXML, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects NessusClientData_v2 at confidence 1.0", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="scan">
    <ReportHost name="host1">
      <ReportItem pluginID="12345"/>
    </ReportHost>
  </Report>
</NessusClientData_v2>`
		fp := registry.GetFingerprint("nessus-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("does not match different XML format", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<testsuites>
  <testsuite name="Suite1"><testcase name="test1"/></testsuite>
</testsuites>`
		fp := registry.GetFingerprint("nessus-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("nessus-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match non-string input", func(t *testing.T) {
		fp := registry.GetFingerprint("nessus-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(map[string]any{"NessusClientData_v2": true}))
	})
}
