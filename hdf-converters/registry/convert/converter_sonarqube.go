package convert

import sonarqube "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sonarqube-to-hdf/go"

func init() {
	registerHDFConverter("sonarqube", "SonarQube to HDF", "sonarqube", sonarqube.ConvertSonarqubeToHDF)
}
