package shared

import (
	"fmt"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// ChainOverrides stamps previousChecksum across amendment overrides in document
// order, linking each to the one before it and leaving the first unlinked.
//
// Every route that authors amendments calls this, so whether a document carries
// tamper-evidence does not depend on which one wrote it. The checksum is
// hdfutil.ChecksumJSON, shared with the TypeScript converters and with
// `hdf amend verify`, so a chain written here verifies everywhere.
func ChainOverrides(overrides []hdf.StandaloneOverride) error {
	var previous *hdf.Checksum
	for i := range overrides {
		overrides[i].PreviousChecksum = previous
		sum, err := hdfutil.ChecksumJSON(overrides[i])
		if err != nil {
			return fmt.Errorf("chaining override %d: %w", i, err)
		}
		previous = &hdf.Checksum{Algorithm: hdf.Sha256, Value: sum}
	}
	return nil
}
