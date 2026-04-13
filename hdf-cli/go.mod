module github.com/mitre/hdf-cli

go 1.26

require (
	github.com/adrg/xdg v0.5.3
	github.com/aws/aws-sdk-go-v2 v1.41.1
	github.com/aws/aws-sdk-go-v2/config v1.32.9
	github.com/aws/aws-sdk-go-v2/service/configservice v1.61.0
	github.com/charmbracelet/bubbles v0.21.1-0.20250623103423-23b8fd6302d7
	github.com/charmbracelet/huh v1.0.0
	github.com/dlclark/regexp2 v1.11.5
	github.com/google/uuid v1.6.0
	github.com/mitre/hdf-converters v0.0.0
	github.com/mitre/hdf-generators/go v0.0.0
	github.com/mitre/hdf-libs/hdf-utilities/go v0.0.0
	github.com/mitre/hdf-schema v0.0.0
	github.com/mitre/hdf-validators/go v0.0.0
	github.com/protobom/protobom v0.5.4
	github.com/spf13/cobra v1.9.1
	github.com/stretchr/testify v1.11.1
	golang.org/x/term v0.41.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/CycloneDX/cyclonedx-go v0.9.2 // indirect
	github.com/anchore/go-struct-converter v0.0.0-20230627203149-c72ef8859ca9 // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.9 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.6 // indirect
	github.com/aws/smithy-go v1.24.0 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/catppuccin/go v0.3.0 // indirect
	github.com/charmbracelet/bubbletea v1.3.6 // indirect
	github.com/charmbracelet/colorprofile v0.2.3-0.20250311203215-f60798e515dc // indirect
	github.com/charmbracelet/lipgloss v1.1.0 // indirect
	github.com/charmbracelet/x/ansi v0.9.3 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.13 // indirect
	github.com/charmbracelet/x/exp/strings v0.0.0-20240722160745-212f7b056ed0 // indirect
	github.com/charmbracelet/x/term v0.2.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/fatih/color v1.15.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2 // indirect
	github.com/mitre/hdf-mappings/go v0.0.0 // indirect
	github.com/mitre/hdf-parsers/go v0.0.0 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/olekukonko/errors v1.1.0 // indirect
	github.com/olekukonko/ll v0.0.9 // indirect
	github.com/olekukonko/tablewriter v1.0.9 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spdx/tools-golang v0.5.5 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	google.golang.org/protobuf v1.36.7 // indirect
	sigs.k8s.io/release-utils v0.12.1 // indirect
)

replace github.com/mitre/hdf-parsers/go => ../hdf-parsers/go

replace github.com/mitre/hdf-converters => ../hdf-converters

replace github.com/mitre/hdf-schema => ../hdf-schema/dist/go

replace github.com/mitre/hdf-mappings/go => ../hdf-mappings/go

replace github.com/mitre/hdf-generators/go => ../hdf-generators/go

replace github.com/mitre/hdf-validators/go => ../hdf-validators/go

replace github.com/mitre/hdf-libs/hdf-utilities/go => ../hdf-utilities/go
