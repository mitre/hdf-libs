package convert

import hadolint "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hadolint-to-hdf/go"

func init() {
	registerHDFConverter("hadolint", "hadolint to HDF", "hadolint", hadolint.ConvertHadolintToHDF,
		WithExpectedRequirementCount(hadolint.ExpectedRequirementCount))
}
