package oscal

import (
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
)

// TestSnapshots asserts the auto-detect entry point reproduces every
// fixtures/expected/<input>.hdf.json golden under the shared TS↔Go snapshot
// harness. All golden inputs are single-document (profiles, which need a
// separate catalog, carry no golden). startTime is input-derived and
// deterministic for these fixtures, so nothing is masked beyond the
// always-masked document timestamp.
func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "oscal-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertOSCALToHDF(input, "1.0.0")
	})
}
