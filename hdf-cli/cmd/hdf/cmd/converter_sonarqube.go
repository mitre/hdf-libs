package cmd

import sonarqube "github.com/mitre/hdf-converters/converters/sonarqube-to-hdf/go"

func init() {
	registerHDFConverter("sonarqube", "SonarQube to HDF", "sonarqube", sonarqube.ConvertSonarqubeToHDF)
}
