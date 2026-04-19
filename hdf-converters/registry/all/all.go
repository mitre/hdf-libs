// Package all imports all converter packages to trigger their init()
// functions, which register fingerprints with the registry.
//
// Usage:
//
//	import _ "github.com/mitre/hdf-converters/registry/all"
//
// This is the Go equivalent of TypeScript's registerAllFingerprints().
package all

// Blank imports below register converter fingerprints via package init().
import (
	// JSON ingest converters.
	_ "github.com/mitre/hdf-converters/converters/aws-config-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/conveyor-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/cyclonedx-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/deptrack-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/gitlab-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/gosec-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/grype-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/jfrog-xray-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/msft-defender-cloud-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/msft-defender-devops-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/msft-defender-endpoint-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/msft-secure-score-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/neuvector-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/sarif-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/scoutsuite-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/snyk-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/sonarqube-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/splunk-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/trufflehog-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/twistlock-to-hdf/go"

	// JSON ingest converters (tool names suggest XML, but input is JSON).
	_ "github.com/mitre/hdf-converters/converters/nikto-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/zap-to-hdf/go"

	// XML ingest converters.
	_ "github.com/mitre/hdf-converters/converters/burpsuite-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/dbprotect-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/fortify-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/junit-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/nessus-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/netsparker-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/veracode-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/xccdf-results-to-hdf/go"

	// Text/CSV ingest.
	_ "github.com/mitre/hdf-converters/converters/prisma-to-hdf/go"

	// HDF native detection.
	_ "github.com/mitre/hdf-converters/converters/hdf-v2-passthrough/go"
	_ "github.com/mitre/hdf-converters/converters/legacyhdf-to-hdf/go"

	// OSCAL converters.
	_ "github.com/mitre/hdf-converters/converters/oscal-to-hdf/go"

	// Export converters.
	_ "github.com/mitre/hdf-converters/converters/hdf-to-csv/go"
	_ "github.com/mitre/hdf-converters/converters/hdf-to-oscal-poam/go"
	_ "github.com/mitre/hdf-converters/converters/hdf-to-oscal-sar/go"
	_ "github.com/mitre/hdf-converters/converters/hdf-to-xml/go"
)
