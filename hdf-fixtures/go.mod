module github.com/mitre/hdf-libs/hdf-fixtures

go 1.26.3

require github.com/mitre/hdf-libs/hdf-validators/go/v3 v3.3.0

require (
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
)

replace github.com/mitre/hdf-libs/hdf-validators/go/v3 => ../hdf-validators/go
