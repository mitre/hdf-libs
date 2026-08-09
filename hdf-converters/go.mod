module github.com/mitre/hdf-libs/hdf-converters/v3

go 1.26.5

require (
	github.com/adrg/xdg v0.5.3
	github.com/aws/aws-sdk-go-v2 v1.43.2
	github.com/aws/aws-sdk-go-v2/config v1.32.33
	github.com/aws/aws-sdk-go-v2/service/configservice v1.68.2
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.75.2
	github.com/mitre/hdf-libs/hdf-fixtures v0.0.0-00010101000000-000000000000
	github.com/mitre/hdf-libs/hdf-mappings/go/v3 v3.5.0
	github.com/mitre/hdf-libs/hdf-parsers/go/v3 v3.5.0
	github.com/mitre/hdf-libs/hdf-schema/dist/go/v3 v3.5.0
	github.com/mitre/hdf-libs/hdf-utilities/go/v3 v3.5.0
	github.com/mitre/hdf-libs/hdf-validators/go/v3 v3.5.0
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2
	github.com/stretchr/testify v1.11.1
	github.com/terminalstatic/go-xsd-validate v0.1.6
	github.com/xeipuuv/gojsonschema v1.2.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.19.32 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.33 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.33 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.33 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.34 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.33 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.5.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.33.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.38.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.45.2 // indirect
	github.com/aws/smithy-go v1.27.5 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)

replace github.com/mitre/hdf-libs/hdf-schema/dist/go/v3 => ../hdf-schema/dist/go

replace github.com/mitre/hdf-libs/hdf-utilities/go/v3 => ../hdf-utilities/go

replace github.com/mitre/hdf-libs/hdf-mappings/go/v3 => ../hdf-mappings/go

replace github.com/mitre/hdf-libs/hdf-validators/go/v3 => ../hdf-validators/go

replace github.com/mitre/hdf-libs/hdf-parsers/go/v3 => ../hdf-parsers/go

replace github.com/mitre/hdf-libs/hdf-fixtures => ../hdf-fixtures
