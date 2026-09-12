module github.com/mitre/hdf-libs/hdf-generators/go/v3

go 1.26.6

require (
	github.com/mitre/hdf-libs/hdf-fixtures/v3 v3.6.0-rc.5
	github.com/mitre/hdf-libs/hdf-schema/dist/go/v3 v3.6.0-rc.5
	github.com/stretchr/testify v1.12.1
)

require go.yaml.in/yaml/v3 v3.0.5 // indirect

replace github.com/mitre/hdf-libs/hdf-fixtures/v3 => ../../hdf-fixtures

replace github.com/mitre/hdf-libs/hdf-schema/dist/go/v3 => ../../hdf-schema/dist/go
