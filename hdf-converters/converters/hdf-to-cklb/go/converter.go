// Package hdftocklb converts HDF Results into a DISA STIG Viewer 3.x checklist
// (.cklb, JSON).
//
// The HDF->checklist mapping and CKLB serialization live in the shared
// checklist package; this converter is a thin wrapper. Any HDF input produces a
// valid CKLB: when the HDF carries checklist passthrough (it originated from a
// CKL/CKLB via the reverse converters), the original fields are reproduced
// losslessly; otherwise the required checklist fields are synthesized
// best-effort from the HDF requirements, tags, and results.
package hdftocklb

import (
	"fmt"

	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/checklist"
)

// ConvertHDFToCKLB converts HDF Results JSON to a STIG Viewer 3.x .cklb (CKLB
// JSON) document. It errors if the input is not valid HDF or has no baselines.
func ConvertHDFToCKLB(input []byte) ([]byte, error) {
	cl, err := checklist.HDFToChecklist(input)
	if err != nil {
		return nil, fmt.Errorf("hdf-to-cklb: %w", err)
	}
	return checklist.SerializeCKLB(cl)
}
