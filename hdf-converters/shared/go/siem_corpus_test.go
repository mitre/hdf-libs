package shared

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The HDF→SIEM exporters share input corpora on purpose: the same HDF document
// fed to each of them is what makes their outputs comparable, and the fixture
// policy's promotion rule ("two or more workspace packages") does not reach
// several converters inside one package. Keeping the copies in place was the
// decision; the risk that decision leaves is silent drift — one copy edited,
// three not — so this pins them byte-identical. Edit every copy or none.
var siemSharedInputs = []struct {
	files []string
	dirs  []string
}{
	{
		files: []string{"cve.json", "compliance.json"},
		dirs:  []string{"hdf-to-asff", "hdf-to-ecs", "hdf-to-ocsf", "hdf-to-splunk"},
	},
	{
		files: []string{"override.json", "riskadjust.json", "negzero.json"},
		dirs:  []string{"hdf-to-ecs", "hdf-to-ocsf", "hdf-to-splunk"},
	},
}

func TestSIEMExportersShareByteIdenticalInputs(t *testing.T) {
	for _, group := range siemSharedInputs {
		for _, name := range group.files {
			t.Run(name, func(t *testing.T) {
				reference := filepath.Join(GetConvertersDir(), group.dirs[0], "fixtures", "input", name)
				want, err := os.ReadFile(reference)
				require.NoError(t, err)
				require.NotEmpty(t, want)
				for _, dir := range group.dirs[1:] {
					path := filepath.Join(GetConvertersDir(), dir, "fixtures", "input", name)
					got, err := os.ReadFile(path)
					require.NoError(t, err, "%s: the shared copy is missing", dir)
					require.True(t, bytes.Equal(want, got),
						"%s/fixtures/input/%s differs from %s's copy — these are one corpus; change every copy together", dir, name, group.dirs[0])
				}
			})
		}
	}
}
