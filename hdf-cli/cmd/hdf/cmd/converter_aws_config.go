package cmd

import awsconfig "github.com/mitre/hdf-libs/hdf-converters/v3/converters/aws-config-to-hdf/go"

func init() {
	registerHDFConverter("aws-config", "AWS Config to HDF", "aws-config", awsconfig.ConvertAWSConfigToHDF)
}
