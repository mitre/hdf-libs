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
// and the linker drops a dataset no reachable code reads — which holds only
// while consumers read these vars inside a loader, never aliasing one at
// package scope, where the load moves into init and so is always reachable.

// NISTDescriptionsRev4 is NIST's own SP 800-53 Rev 4 control titles and statement text,
// keyed by padded identifier.
//
//go:embed catalogs/nist-descriptions.json
var NISTDescriptionsRev4 []byte

// NISTDescriptionsRev5 is NIST's own SP 800-53 Rev 5 control titles and statement text,
// keyed by padded identifier.
//
//go:embed catalogs/nist-descriptions-rev5.json
var NISTDescriptionsRev5 []byte

// NISTRevisionCrosswalk is NIST's Rev 4 to Rev 5 control correspondence, plus the per-
// revision control roster.
//
//go:embed mappings/nist-revision-crosswalk.json
var NISTRevisionCrosswalk []byte

// CCIMappings is DISA's CCI list keyed by CCI, carrying each item's definition and its
// NIST 800-53 references.
//
//go:embed mappings/cci-mappings.json
var CCIMappings []byte

// NISTCCIMappings is the reverse index: NIST 800-53 control to the CCIs that cite it.
//
//go:embed mappings/nist-cci-mappings.json
var NISTCCIMappings []byte

// CWENIST maps CWE weakness IDs to NIST 800-53 controls.
//
//go:embed mappings/cwe-nist-mappings.json
var CWENIST []byte

// OWASPNIST maps OWASP Top 10 category IDs to NIST 800-53 controls.
//
//go:embed mappings/owasp-nist-mappings.json
var OWASPNIST []byte

// AWSConfigMappings maps AWS Config rule names and source identifiers to NIST 800-53
// controls.
//
//go:embed mappings/awsconfig-mappings.json
var AWSConfigMappings []byte

// CheckovCCINIST maps Checkov check IDs to CCIs and NIST 800-53 controls.
//
//go:embed mappings/checkov-cci-nist-mappings.json
var CheckovCCINIST []byte

// HadolintNIST maps Hadolint rule IDs to NIST 800-53 controls.
//
//go:embed mappings/hadolint-nist-mappings.json
var HadolintNIST []byte

// HipcheckNIST maps Hipcheck analysis names to NIST 800-53 controls.
//
//go:embed mappings/hipcheck-nist-mappings.json
var HipcheckNIST []byte

// NessusNIST maps Nessus plugin families and plugin IDs to NIST 800-53 controls.
//
//go:embed mappings/nessus-nist-mappings.json
var NessusNIST []byte

// NiktoNIST maps Nikto test IDs to NIST 800-53 controls.
//
//go:embed mappings/nikto-nist-mappings.json
var NiktoNIST []byte

// ScoutSuiteNIST maps ScoutSuite rule names to NIST 800-53 controls.
//
//go:embed mappings/scoutsuite-nist-mappings.json
var ScoutSuiteNIST []byte
