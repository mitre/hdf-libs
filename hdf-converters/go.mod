module github.com/mitre/hdf-converters

go 1.23

require (
	github.com/mitre/hdf-mappings/go v0.0.0
	github.com/mitre/hdf-schema v0.0.0
	github.com/stretchr/testify v1.9.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/mitre/hdf-schema => ../hdf-schema/dist/go

replace github.com/mitre/hdf-mappings/go => ../hdf-mappings/go
