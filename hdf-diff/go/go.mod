module github.com/mitre/hdf-libs/hdf-diff/go/v3

go 1.26.6

require (
	github.com/mitre/hdf-libs/hdf-schema/dist/go/v3 v3.5.1
	github.com/mitre/hdf-libs/hdf-schema/testhdf/go v0.0.0-00010101000000-000000000000
	github.com/mitre/hdf-libs/hdf-utilities/go/v3 v3.5.1
	github.com/mitre/hdf-libs/hdf-validators/go/v3 v3.5.0
	github.com/protobom/protobom v0.6.0
	github.com/stretchr/testify v1.12.1
)

require (
	github.com/CycloneDX/cyclonedx-go v0.11.0 // indirect
	github.com/anchore/go-struct-converter v0.1.0 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/carabiner-dev/spdx3 v0.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/clipperhouse/displaywidth v0.10.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.6.0 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.19 // indirect
	github.com/olekukonko/cat v0.0.0-20250911104152-50322a0618f6 // indirect
	github.com/olekukonko/errors v1.2.0 // indirect
	github.com/olekukonko/ll v0.1.6 // indirect
	github.com/olekukonko/tablewriter v1.1.4 // indirect
	github.com/sirupsen/logrus v1.10.1 // indirect
	github.com/spdx/tools-golang v0.5.7 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.44.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	sigs.k8s.io/release-utils v0.12.4 // indirect
)

replace github.com/mitre/hdf-libs/hdf-schema/dist/go/v3 => ../../hdf-schema/dist/go

replace github.com/mitre/hdf-libs/hdf-schema/testhdf/go => ../../hdf-schema/testhdf/go

replace github.com/mitre/hdf-libs/hdf-validators/go/v3 => ../../hdf-validators/go

replace github.com/mitre/hdf-libs/hdf-utilities/go/v3 => ../../hdf-utilities/go
