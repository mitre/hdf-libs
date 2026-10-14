package convert

import grype "github.com/mitre/hdf-libs/hdf-converters/v3/converters/grype-to-hdf/go"

func init() {
	registerHDFConverter("grype", "Grype to HDF", "grype", grype.ConvertGrypeToHDF,
		WithExpectedRequirementCount(grype.ExpectedRequirementCount),
		// Roll-up moves the finding count off the requirements, so the result
		// count is the only under-extraction guard left — registration refuses
		// the pair if it is missing.
		WithExpectedResultCount(grype.ExpectedResultCount),
		WithRequirementRollUp(),
	)
}
