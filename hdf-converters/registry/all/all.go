// Package all imports all converter packages to trigger their init()
// functions, which register fingerprints with the registry.
//
// Usage:
//
//	import _ "github.com/mitre/hdf-converters/registry/all"
//
// This is the Go equivalent of TypeScript's registerAllFingerprints().
package all

// JSON ingest converters
import (
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
)

// JSON ingest converters (input is JSON despite tool names suggesting XML)
import (
	_ "github.com/mitre/hdf-converters/converters/nikto-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/zap-to-hdf/go"
)

// XML ingest converters
import (
	_ "github.com/mitre/hdf-converters/converters/burpsuite-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/dbprotect-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/fortify-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/junit-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/nessus-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/netsparker-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/veracode-to-hdf/go"
	_ "github.com/mitre/hdf-converters/converters/xccdf-results-to-hdf/go"
)

// Text/CSV ingest
import (
	_ "github.com/mitre/hdf-converters/converters/prisma-to-hdf/go"
)

// HDF native detection
import (
	_ "github.com/mitre/hdf-converters/converters/hdf-v2-passthrough/go"
	_ "github.com/mitre/hdf-converters/converters/legacyhdf-to-hdf/go"
)

// OSCAL converters
import (
	_ "github.com/mitre/hdf-converters/converters/oscal-to-hdf/go"
)

// Export converters
import (
	_ "github.com/mitre/hdf-converters/converters/hdf-to-csv/go"
	_ "github.com/mitre/hdf-converters/converters/hdf-to-oscal-poam/go"
	_ "github.com/mitre/hdf-converters/converters/hdf-to-oscal-sar/go"
	_ "github.com/mitre/hdf-converters/converters/hdf-to-xml/go"
)
