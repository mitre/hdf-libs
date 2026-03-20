package junit

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJunitFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("junit-to-hdf")
		require.NotNil(t, fp, "junit-to-hdf should be registered via init()")
		assert.Equal(t, "JUnit", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyXML, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects testsuites root at confidence 1.0", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<testsuites name="AllTests" tests="10" failures="2">
  <testsuite name="Suite1" tests="5" failures="1">
    <testcase name="test1"/>
  </testsuite>
</testsuites>`
		fp := registry.GetFingerprint("junit-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects testsuite root at confidence 1.0", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<testsuite name="Suite1" tests="5" failures="1">
  <testcase name="test1"/>
</testsuite>`
		fp := registry.GetFingerprint("junit-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("does not match different XML format", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<FVDL xmlns="xmlns.fortify.com/schema/fvdl" version="1.12">
  <Build/>
</FVDL>`
		fp := registry.GetFingerprint("junit-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("junit-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match non-string input", func(t *testing.T) {
		fp := registry.GetFingerprint("junit-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(map[string]any{"testsuites": true}))
	})
}
