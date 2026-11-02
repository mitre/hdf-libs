// Package datasets holds every mapping dataset this module ships and nothing else.
//
// The datasets live apart from the code that reads them, so each exists once
// and both languages read that one copy: Go through the vars below, TypeScript
// by importing the same file. They sit in a Go package because an embed pattern
// cannot reach outside the package directory that declares it.
//
// catalogs/ carries an authority's own text, where wrong means stale.
// mappings/ carries correspondences between identifier spaces, where each row
// is an editorial judgement and wrong means mistaken.
package datasets

import _ "embed"

// One var per dataset rather than a single embed.FS, deliberately: a filename
// typo is then a compile error, the bytes are the image rather than a heap copy,
// and the linker drops the datasets a program never names. An FS behind a
// lookup forfeits all three, and costs every consumer the whole corpus.

//go:embed catalogs/nist-descriptions.json
var NISTDescriptionsRev4 []byte

//go:embed catalogs/nist-descriptions-rev5.json
var NISTDescriptionsRev5 []byte

//go:embed mappings/nist-revision-crosswalk.json
var NISTRevisionCrosswalk []byte

//go:embed mappings/cci-mappings.json
var CCIMappings []byte

//go:embed mappings/nist-cci-mappings.json
var NISTCCIMappings []byte

//go:embed mappings/cwe-nist-mappings.json
var CWENIST []byte

//go:embed mappings/owasp-nist-mappings.json
var OWASPNIST []byte

//go:embed mappings/awsconfig-mappings.json
var AWSConfigMappings []byte

//go:embed mappings/checkov-cci-nist-mappings.json
var CheckovCCINIST []byte

//go:embed mappings/hadolint-nist-mappings.json
var HadolintNIST []byte

//go:embed mappings/hipcheck-nist-mappings.json
var HipcheckNIST []byte

//go:embed mappings/nessus-nist-mappings.json
var NessusNIST []byte

//go:embed mappings/nikto-nist-mappings.json
var NiktoNIST []byte

//go:embed mappings/scoutsuite-nist-mappings.json
var ScoutSuiteNIST []byte
