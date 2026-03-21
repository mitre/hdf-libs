package burpsuite

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBurpsuiteFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("burpsuite-to-hdf")
		require.NotNil(t, fp, "burpsuite-to-hdf should be registered via init()")
		assert.Equal(t, "Burp Suite", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyXML, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects BurpSuite XML with burpVersion at confidence 1.0", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<issues burpVersion="2023.1.2" exportTime="Thu Jan 01 00:00:00 UTC 2023">
  <issue><serialNumber>1234</serialNumber></issue>
</issues>`
		fp := registry.GetFingerprint("burpsuite-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects issues root without burpVersion at confidence 0.7", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<issues>
  <issue><serialNumber>1234</serialNumber></issue>
</issues>`
		fp := registry.GetFingerprint("burpsuite-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.7, fp.Fingerprint(input))
	})

	t.Run("does not match different XML format", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="scan"><ReportHost name="host1"></ReportHost></Report>
</NessusClientData_v2>`
		fp := registry.GetFingerprint("burpsuite-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("burpsuite-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match non-string input", func(t *testing.T) {
		fp := registry.GetFingerprint("burpsuite-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(map[string]any{"issues": true}))
	})
}
