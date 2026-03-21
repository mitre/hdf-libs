package fortify

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFortifyFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("fortify-to-hdf")
		require.NotNil(t, fp, "fortify-to-hdf should be registered via init()")
		assert.Equal(t, "Fortify", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyXML, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects Fortify FVDL with namespace at confidence 1.0", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<FVDL xmlns="xmlns.fortify.com/schema/fvdl" version="1.12">
  <Build><SourceFiles><File size="1234" type="java"/></SourceFiles></Build>
</FVDL>`
		fp := registry.GetFingerprint("fortify-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects FVDL without Fortify namespace at confidence 0.95", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<FVDL version="1.12">
  <Build><SourceFiles><File size="1234" type="java"/></SourceFiles></Build>
</FVDL>`
		fp := registry.GetFingerprint("fortify-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.95, fp.Fingerprint(input))
	})

	t.Run("does not match different XML format", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="scan"><ReportHost name="host1"></ReportHost></Report>
</NessusClientData_v2>`
		fp := registry.GetFingerprint("fortify-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("fortify-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match non-string input", func(t *testing.T) {
		fp := registry.GetFingerprint("fortify-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(map[string]any{"FVDL": true}))
	})
}
