package spdxvex

import (
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/bom"
)

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "spdx-vex-to-hdf",
		Label:       "SPDX 3.0 Security VEX",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputAmendments,
		// Reuse the shared BOM-package detector: an SPDX-3 JSON-LD document whose
		// @graph carries at least one security_Vex*VulnAssessmentRelationship.
		// Disjoint from DetectSPDX3 (AI/Dataset) and from SPDX 2.x by construction.
		Fingerprint: bom.DetectSPDX3Security,
	})
}
