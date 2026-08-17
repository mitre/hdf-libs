module github.com/mitre/hdf-libs/hdf-generators/go/v3

go 1.26.6

require (
	github.com/mitre/hdf-libs/hdf-fixtures v0.0.0-00010101000000-000000000000
	github.com/mitre/hdf-libs/hdf-schema/dist/go/v3 v3.5.1
	github.com/stretchr/testify v1.12.0
)

require gopkg.in/yaml.v3 v3.0.1 // indirect

replace github.com/mitre/hdf-libs/hdf-fixtures => ../../hdf-fixtures

replace github.com/mitre/hdf-libs/hdf-schema/dist/go/v3 => ../../hdf-schema/dist/go
