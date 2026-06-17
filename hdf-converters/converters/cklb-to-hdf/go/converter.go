// Package cklb converts DISA STIG Viewer 3.x checklist (.cklb) JSON into HDF Results.
//
// CKLB is the JSON checklist format produced by the DISA STIG Viewer 3.x GUI
// (the successor to the legacy .ckl XML format): an assessor records a status
// (open / not_a_finding / not_reviewed / not_applicable) per STIG rule. Parsing
// and the HDF mapping live in the shared checklist package, which the
// ckl-to-hdf, hdf-to-ckl, and hdf-to-cklb converters share.
//
// v3.2 classification fields: controlType is derived per-rule from the CCI ->
// NIST mapping. verificationMethod is deliberately NOT set — the CKLB format
// does not guarantee whether a finding was assessed manually,
// automated-then-exported, or mixed, so stamping a constant would assert a
// classification the source cannot substantiate. applicability is omitted
// likewise (a not_applicable status is an assessment outcome, not a baseline
// applicability marker). See .claude/commands/build-converter.md Step 4d.
package cklb

import (
	"fmt"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/checklist"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// maxInputSize caps CKLB JSON input at 50MB.
const maxInputSize = 50 * 1024 * 1024

// ConvertCKLBToHDF converts a DISA STIG Viewer 3.x .cklb document to HDF Results.
func ConvertCKLBToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if err := shared.ValidateJSONSize(input, "cklb", maxInputSize); err != nil {
		return nil, fmt.Errorf("cklb: %w", err)
	}
	cl, err := checklist.ParseCKLB(input)
	if err != nil {
		return nil, fmt.Errorf("cklb: %w", err)
	}
	return checklist.ChecklistToHDF(cl, shared.InputChecksum(input), converterVersion, "cklb-to-hdf"), nil
}
