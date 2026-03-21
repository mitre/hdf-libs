package netsparker

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetsparkerFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("netsparker-to-hdf")
		require.NotNil(t, fp, "netsparker-to-hdf should be registered via init()")
		assert.Equal(t, "Netsparker", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyXML, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects netsparker-enterprise root at confidence 1.0", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<netsparker-enterprise>
  <target><url>https://example.com</url></target>
  <vulnerabilities/>
</netsparker-enterprise>`
		fp := registry.GetFingerprint("netsparker-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects invicti-enterprise root at confidence 1.0", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<invicti-enterprise>
  <target><url>https://example.com</url></target>
  <vulnerabilities/>
</invicti-enterprise>`
		fp := registry.GetFingerprint("netsparker-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("does not match different XML format", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="scan"/>
</NessusClientData_v2>`
		fp := registry.GetFingerprint("netsparker-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("netsparker-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match non-string input", func(t *testing.T) {
		fp := registry.GetFingerprint("netsparker-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(map[string]any{"netsparker": true}))
	})
}
