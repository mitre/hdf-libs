/**
 * @mitre/hdf-converters
 *
 * Converters for security tool outputs and HDF format versions
 */

// Legacy HDF (v1.0) to HDF v2.0 converter
export {
  convertV1ToV2,
  isHDFV1,
  type HDFV1Results,
  type HDFV2Results,
} from '../converters/legacyhdf-to-hdf/typescript/index.js';

// SARIF to HDF converter
export { convertSarifToHdf } from '../converters/sarif-to-hdf/typescript/index.js';

// JUnit XML to HDF converter
export { convertJunitToHdf } from '../converters/junit-to-hdf/typescript/index.js';

// XCCDF Results to HDF converter
export { convertXccdfResultsToHdf } from '../converters/xccdf-results-to-hdf/typescript/index.js';

// Snyk to HDF converter
export { convertSnykToHdf } from '../converters/snyk-to-hdf/typescript/index.js';

// Grype to HDF converter
export { convertGrypeToHdf } from '../converters/grype-to-hdf/typescript/index.js';

// Nessus to HDF converter
export { convertNessusToHdf } from '../converters/nessus-to-hdf/typescript/index.js';

// SonarQube to HDF converter
export { convertSonarqubeToHdf } from '../converters/sonarqube-to-hdf/typescript/index.js';

// AWS Config to HDF converter
export { convertAwsConfigToHdf } from '../converters/aws-config-to-hdf/typescript/index.js';

// Gosec to HDF converter
export { convertGosecToHdf } from '../converters/gosec-to-hdf/typescript/index.js';

// Nikto to HDF converter
export { convertNiktoToHdf } from '../converters/nikto-to-hdf/typescript/index.js';

// OWASP ZAP to HDF converter
export { convertZapToHdf } from '../converters/zap-to-hdf/typescript/index.js';

// CycloneDX SBOM/VEX to HDF converter
export { convertCyclonedxToHdf } from '../converters/cyclonedx-to-hdf/typescript/index.js';

// HDF to CSV converter
export { convertHdfToCsv } from '../converters/hdf-to-csv/typescript/index.js';

// Splunk to HDF converter
export { convertSplunkToHdf } from '../converters/splunk-to-hdf/typescript/index.js';

// HDF to XML converter
export { convertHdfToXml } from '../converters/hdf-to-xml/typescript/index.js';

// GitLab Security Report to HDF converter
export { convertGitlabToHdf } from '../converters/gitlab-to-hdf/typescript/index.js';

// TruffleHog to HDF converter
export { convertTrufflehogToHdf } from '../converters/trufflehog-to-hdf/typescript/index.js';

// BurpSuite to HDF converter
export { convertBurpsuiteToHdf } from '../converters/burpsuite-to-hdf/typescript/index.js';

// DBProtect to HDF converter
export { convertDbprotectToHdf } from '../converters/dbprotect-to-hdf/typescript/index.js';

// Twistlock to HDF converter
export { convertTwistlockToHdf } from '../converters/twistlock-to-hdf/typescript/index.js';

// Dependency-Track to HDF converter
export { convertDeptrackToHdf } from '../converters/deptrack-to-hdf/typescript/index.js';

// JFrog Xray to HDF converter
export { convertJfrogXrayToHdf } from '../converters/jfrog-xray-to-hdf/typescript/index.js';

// NeuVector to HDF converter
export { convertNeuvectorToHdf } from '../converters/neuvector-to-hdf/typescript/index.js';

// Fortify to HDF converter
export { convertFortifyToHdf } from '../converters/fortify-to-hdf/typescript/index.js';

// Prisma Cloud to HDF converter
export { convertPrismaToHdf } from '../converters/prisma-to-hdf/typescript/index.js';

// Netsparker/Invicti to HDF converter
export { convertNetsparkerToHdf } from '../converters/netsparker-to-hdf/typescript/index.js';

// ScoutSuite to HDF converter
export { convertScoutsuiteToHdf } from '../converters/scoutsuite-to-hdf/typescript/index.js';

// Conveyor to HDF converter
export { convertConveyorToHdf } from '../converters/conveyor-to-hdf/typescript/index.js';

// Veracode to HDF converter
export { convertVeracodeToHdf } from '../converters/veracode-to-hdf/typescript/index.js';

// Microsoft Secure Score to HDF converter
export { convertMsftSecureScoreToHdf } from '../converters/msft-secure-score-to-hdf/typescript/index.js';
