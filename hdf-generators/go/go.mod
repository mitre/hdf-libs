module github.com/mitre/hdf-generators/go

go 1.26

require (
	github.com/mitre/hdf-schema v0.0.0
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/mitre/hdf-schema => ../../hdf-schema/dist/go
