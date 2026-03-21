package xccdf

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXccdfFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("xccdf-results-to-hdf")
		require.NotNil(t, fp, "xccdf-results-to-hdf should be registered via init()")
		assert.Equal(t, "XCCDF/ARF", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyXML, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects Benchmark root at confidence 1.0", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_benchmark_1">
  <status>accepted</status>
  <Rule id="rule_1"><title>Test Rule</title></Rule>
</Benchmark>`
		fp := registry.GetFingerprint("xccdf-results-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects namespaced Benchmark at confidence 1.0", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="xccdf_benchmark_1">
  <xccdf:status>accepted</xccdf:status>
</xccdf:Benchmark>`
		fp := registry.GetFingerprint("xccdf-results-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects asset-report-collection root at confidence 1.0", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<asset-report-collection xmlns="http://scap.nist.gov/schema/asset-reporting-format/1.1">
  <report-requests/>
  <assets/>
  <reports/>
</asset-report-collection>`
		fp := registry.GetFingerprint("xccdf-results-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects namespaced asset-report-collection at confidence 1.0", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<arf:asset-report-collection xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1">
  <arf:report-requests/>
</arf:asset-report-collection>`
		fp := registry.GetFingerprint("xccdf-results-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("does not match different XML format", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<FVDL xmlns="xmlns.fortify.com/schema/fvdl" version="1.12">
  <Build/>
</FVDL>`
		fp := registry.GetFingerprint("xccdf-results-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("xccdf-results-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match non-string input", func(t *testing.T) {
		fp := registry.GetFingerprint("xccdf-results-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(map[string]any{"Benchmark": true}))
	})
}
