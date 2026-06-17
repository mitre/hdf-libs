// Package ckl converts DISA STIG Viewer checklist (.ckl) XML into HDF Results.
//
// CKL is the manual-fill checklist format produced by the DISA STIG Viewer
// GUI: an assessor records a STATUS (Open / NotAFinding / Not_Reviewed /
// Not_Applicable) per STIG rule. Parsing and the HDF mapping live in the
// shared checklist package, which the cklb-to-hdf, hdf-to-ckl, and hdf-to-cklb
// converters share.
//
// v3.2 classification fields: controlType is derived per-VULN from the CCI ->
// NIST mapping. verificationMethod is deliberately NOT set — the CKL format
// does not guarantee whether a finding was assessed manually,
// automated-then-exported, or mixed, so stamping a constant would assert a
// classification the source cannot substantiate. applicability is omitted
// likewise (a Not_Applicable STATUS is an assessment outcome, not a baseline
// applicability marker). See .claude/commands/build-converter.md Step 4d.
package ckl

import (
	"fmt"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/checklist"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// maxInputSize caps CKL input at 50MB (entity-expansion + size guard).
const maxInputSize = 50 * 1024 * 1024

// ConvertCKLToHDF converts a DISA STIG Viewer .ckl document to HDF Results.
func ConvertCKLToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if err := shared.ValidateXMLInput(input, maxInputSize); err != nil {
		return nil, fmt.Errorf("ckl: %w", err)
	}
	cl, err := checklist.ParseCKL(input)
	if err != nil {
		return nil, fmt.Errorf("ckl: %w", err)
	}
	return checklist.ChecklistToHDF(cl, shared.InputChecksum(input), converterVersion, "ckl-to-hdf"), nil
}
