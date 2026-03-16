package cmd

import deptrack "github.com/mitre/hdf-converters/converters/deptrack-to-hdf/go"

func init() {
	registerHDFConverter("deptrack", "Dependency-Track to HDF", "deptrack", deptrack.ConvertDeptrackToHDF)
	registerHDFConverter("dependency-track", "Dependency-Track to HDF", "deptrack", deptrack.ConvertDeptrackToHDF)
}
