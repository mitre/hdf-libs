package convert

import nexusiq "github.com/mitre/hdf-libs/hdf-converters/v3/converters/nexusiq-to-hdf/go"

func init() {
	registerHDFConverterMulti(
		[]string{"nexusiq", "sonatype", "lifecycle"},
		"Nexus IQ to HDF", "nexusiq",
		nexusiq.ConvertNexusIQToHDF,
		WithExpectedRequirementCount(nexusiq.ExpectedRequirementCount),
	)
}
