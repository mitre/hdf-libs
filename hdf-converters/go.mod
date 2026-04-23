module github.com/mitre/hdf-libs/hdf-converters

go 1.26

require (
	github.com/mitre/hdf-libs/hdf-mappings/go v0.0.0
	github.com/mitre/hdf-libs/hdf-parsers/go v0.0.0
	github.com/mitre/hdf-libs/hdf-schema/dist/go v0.0.0
	github.com/mitre/hdf-libs/hdf-utilities/go v0.0.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/mitre/hdf-libs/hdf-validators/go v0.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/mitre/hdf-libs/hdf-schema/dist/go => ../hdf-schema/dist/go

replace github.com/mitre/hdf-libs/hdf-utilities/go => ../hdf-utilities/go

replace github.com/mitre/hdf-libs/hdf-mappings/go => ../hdf-mappings/go

replace github.com/mitre/hdf-libs/hdf-validators/go => ../hdf-validators/go

replace github.com/mitre/hdf-libs/hdf-parsers/go => ../hdf-parsers/go
