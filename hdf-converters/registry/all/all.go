// Package all imports all converter packages to trigger their init()
// functions, which register fingerprints with the registry.
//
// Usage:
//
//	import _ "github.com/mitre/hdf-libs/hdf-converters/v3/registry/all"
//
// This is the Go equivalent of TypeScript's registerAllFingerprints().
package all

// Blank imports below register converter fingerprints via package init().
import (
	// JSON ingest converters.
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/aws-config-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/cklb-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/conveyor-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/csaf-vex-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/cyclonedx-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/cyclonedx-vex-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/deptrack-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/gitlab-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/gosec-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/grype-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/jfrog-xray-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/msft-defender-cloud-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/msft-defender-devops-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/msft-defender-endpoint-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/msft-secure-score-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/neuvector-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/openvex-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sarif-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/scoutsuite-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/snyk-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sonarqube-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/spdx-vex-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/splunk-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/trivy-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/trufflehog-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/twistlock-to-hdf/go"

	// JSON ingest converters (tool names suggest XML, but input is JSON).
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/nikto-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/zap-to-hdf/go"

	// XML ingest converters.
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/burpsuite-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/ckl-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/dbprotect-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/fortify-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/junit-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/nessus-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/netsparker-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/veracode-to-hdf/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/xccdf-results-to-hdf/go"

	// Text/CSV ingest.
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/prisma-to-hdf/go"

	// HDF native detection.
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-passthrough/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/legacyhdf-to-hdf/go"

	// OSCAL converters.
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"

	// Export converters.
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-csv/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-oscal-poam/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-oscal-sar/go"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-xml/go"
)
