package convert

import deptrack "github.com/mitre/hdf-libs/hdf-converters/v3/converters/deptrack-to-hdf/go"

func init() {
	registerHDFConverter("deptrack", "Dependency-Track to HDF", "deptrack", deptrack.ConvertDeptrackToHDF, WithExpectedRequirementCount(deptrack.ExpectedRequirementCount))
	registerHDFConverter("dependency-track", "Dependency-Track to HDF", "deptrack", deptrack.ConvertDeptrackToHDF, WithExpectedRequirementCount(deptrack.ExpectedRequirementCount))
}
