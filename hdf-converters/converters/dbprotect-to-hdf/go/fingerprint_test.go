package dbprotect

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDbprotectFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("dbprotect-to-hdf")
		require.NotNil(t, fp, "dbprotect-to-hdf should be registered via init()")
		assert.Equal(t, "DBProtect", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyXML, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects DBProtect XML with metadata and data at confidence 1.0", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<dataset>
  <metadata><item name="col1" type="string"/></metadata>
  <data><row><value>cell1</value></row></data>
</dataset>`
		fp := registry.GetFingerprint("dbprotect-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects dataset root without metadata/data at confidence 0.8", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<dataset>
  <other>content</other>
</dataset>`
		fp := registry.GetFingerprint("dbprotect-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.8, fp.Fingerprint(input))
	})

	t.Run("does not match different XML format", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<testsuites>
  <testsuite name="test"><testcase name="case1"/></testsuite>
</testsuites>`
		fp := registry.GetFingerprint("dbprotect-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("dbprotect-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match non-string input", func(t *testing.T) {
		fp := registry.GetFingerprint("dbprotect-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(map[string]any{"dataset": true}))
	})
}
