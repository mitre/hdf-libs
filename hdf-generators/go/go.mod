module github.com/mitre/hdf-libs/hdf-generators/go/v3

go 1.26.11

require (
	github.com/mitre/hdf-libs/hdf-fixtures/v3 v3.8.0-next.43322455428.1
	github.com/mitre/hdf-libs/hdf-schema/dist/go/v3 v3.8.0-next.43322455428.1
	github.com/stretchr/testify v1.12.1
)

require go.yaml.in/yaml/v3 v3.0.5 // indirect

replace github.com/mitre/hdf-libs/hdf-fixtures/v3 => ../../hdf-fixtures

replace github.com/mitre/hdf-libs/hdf-schema/dist/go/v3 => ../../hdf-schema/dist/go
