module github.com/mitre/hdf-libs/hdf-diff/go/v3

go 1.26.5

require (
	github.com/mitre/hdf-libs/hdf-schema/dist/go/v3 v3.4.0
	github.com/mitre/hdf-libs/hdf-utilities/go/v3 v3.4.0
	github.com/protobom/protobom v0.5.4
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/CycloneDX/cyclonedx-go v0.9.2 // indirect
	github.com/anchore/go-struct-converter v0.0.0-20230627203149-c72ef8859ca9 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/clipperhouse/stringish v0.1.1 // indirect
	github.com/clipperhouse/uax29/v2 v2.5.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fatih/color v1.15.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.19 // indirect
	github.com/olekukonko/errors v1.1.0 // indirect
	github.com/olekukonko/ll v0.0.9 // indirect
	github.com/olekukonko/tablewriter v1.0.9 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spdx/tools-golang v0.5.5 // indirect
	golang.org/x/sys v0.44.0 // indirect
	google.golang.org/protobuf v1.36.7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	sigs.k8s.io/release-utils v0.12.1 // indirect
)

replace github.com/mitre/hdf-libs/hdf-schema/dist/go/v3 => ../../hdf-schema/dist/go

replace github.com/mitre/hdf-libs/hdf-utilities/go/v3 => ../../hdf-utilities/go
