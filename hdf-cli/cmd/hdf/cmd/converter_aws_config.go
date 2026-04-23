package cmd

import awsconfig "github.com/mitre/hdf-libs/hdf-converters/converters/aws-config-to-hdf/go"

func init() {
	registerHDFConverter("aws-config", "AWS Config to HDF", "aws-config", awsconfig.ConvertAWSConfigToHDF)
}
