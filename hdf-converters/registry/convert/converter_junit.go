package convert

import junit "github.com/mitre/hdf-libs/hdf-converters/v3/converters/junit-to-hdf/go"

func init() {
	registerHDFConverter("junit", "JUnit to HDF", "junit", junit.ConvertJUnitToHDF)
}
