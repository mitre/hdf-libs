// Package hdftockl converts HDF Results into a DISA STIG Viewer checklist
// (.ckl XML).
//
// This is a thin wrapper over the shared checklist package, mirroring the
// hdf-to-csv reverse converter. It produces a STIG Viewer 2.x .ckl from ANY
// HDF: when the HDF carries checklist passthrough (extensions/tags written by
// a prior ckl/cklb-to-hdf conversion) the original fields are reproduced
// losslessly; otherwise the required checklist fields are synthesized
// best-effort (id->Vuln_Num, nist->CCI reverse, status reverse) with safe
// defaults. Mirrors heimdall2 PR #4841.
package hdftockl

import (
	"fmt"

	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/checklist"
)

// ConvertHDFToCKL converts HDF Results JSON to a DISA STIG Viewer .ckl XML
// document. It errors on invalid JSON or HDF with no baselines.
func ConvertHDFToCKL(input []byte) ([]byte, error) {
	cl, err := checklist.HDFToChecklist(input)
	if err != nil {
		return nil, fmt.Errorf("hdf-to-ckl: %w", err)
	}
	return checklist.SerializeCKL(cl)
}
