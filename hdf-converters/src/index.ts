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
