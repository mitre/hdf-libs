module github.com/mitre/hdf-cli

go 1.23

require (
	github.com/dlclark/regexp2 v1.11.5
	github.com/mitre/hdf-converters v0.0.0
	github.com/mitre/hdf-validators/go v0.0.0
	github.com/spf13/cobra v1.8.1
	github.com/stretchr/testify v1.10.0
	github.com/xeipuuv/gojsonschema v1.2.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mitre/hdf-mappings/go v0.0.0 // indirect
	github.com/mitre/hdf-schema v0.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/mitre/hdf-converters => ../hdf-converters

replace github.com/mitre/hdf-schema => ../hdf-schema/dist/go

replace github.com/mitre/hdf-mappings/go => ../hdf-mappings/go

replace github.com/mitre/hdf-validators/go => ../hdf-validators/go
