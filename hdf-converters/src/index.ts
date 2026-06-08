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

// CKL (DISA STIG Viewer checklist) to HDF converter
export { convertCklToHdf } from '../converters/ckl-to-hdf/typescript/index.js';

// CKLB (DISA STIG Viewer 3.x JSON checklist) to HDF converter
export { convertCklbToHdf } from '../converters/cklb-to-hdf/typescript/index.js';

// HDF to CKL / CKLB (DISA STIG Viewer checklist) converters
export { convertHdfToCkl } from '../converters/hdf-to-ckl/typescript/index.js';
export { convertHdfToCklb } from '../converters/hdf-to-cklb/typescript/index.js';

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

// Checkov to HDF converter
export { convertCheckovToHdf } from '../converters/checkov-to-hdf/typescript/index.js';

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

// Microsoft Defender for DevOps to HDF converter
export { convertMsftDefenderDevopsToHdf } from '../converters/msft-defender-devops-to-hdf/typescript/index.js';

// Microsoft Defender for Cloud to HDF converter
export { convertMsftDefenderCloudToHdf } from '../converters/msft-defender-cloud-to-hdf/typescript/index.js';

// Microsoft Defender for Endpoint to HDF converter
export { convertMsftDefenderEndpointToHdf } from '../converters/msft-defender-endpoint-to-hdf/typescript/index.js';

// HDF to XCCDF converter
export { convertHdfToXccdf } from '../converters/hdf-to-xccdf/typescript/index.js';

// HDF to OSCAL SAR converter
export { convertHdfToOscalSar } from '../converters/hdf-to-oscal-sar/typescript/index.js';

// HDF to OSCAL POA&M converter
export { convertHdfToOscalPoam } from '../converters/hdf-to-oscal-poam/typescript/index.js';

// Ion Channel to HDF converter
export { convertIonchannelToHdf } from '../converters/ionchannel-to-hdf/typescript/index.js';

// OpenVEX to HDF Amendments converter
export { convertOpenVexToHdf } from '../converters/openvex-to-hdf/typescript/index.js';

// CSAF VEX to HDF Amendments converter
export { convertCsafVexToHdf } from '../converters/csaf-vex-to-hdf/typescript/index.js';

// CycloneDX VEX to HDF Amendments converter
export { convertCyclonedxVexToHdf } from '../converters/cyclonedx-vex-to-hdf/typescript/index.js';

// HDF Amendments to CSAF VEX converter (export side; partial-fidelity by design)
export { convertHdfToCsafVex } from '../converters/hdf-to-csaf-vex/typescript/index.js';

// HDF Amendments to OpenVEX converter (export side; partial-fidelity by design)
export { convertHdfToOpenVex } from '../converters/hdf-to-openvex/typescript/index.js';

// HDF Amendments to CycloneDX VEX converter (export side; partial-fidelity by design)
export { convertHdfToCyclonedxVex } from '../converters/hdf-to-cyclonedx-vex/typescript/index.js';

// OSCAL to HDF converters
export { convertOscalCatalogToHdf } from '../converters/oscal-to-hdf/typescript/index.js';
export { convertOscalProfileToHdf } from '../converters/oscal-to-hdf/typescript/index.js';
export { convertOscalComponentToHdf } from '../converters/oscal-to-hdf/typescript/index.js';
export { convertOscalSspToHdf } from '../converters/oscal-to-hdf/typescript/index.js';
export { convertOscalSapToHdf } from '../converters/oscal-to-hdf/typescript/index.js';
export { convertOscalPoamToHdf } from '../converters/oscal-to-hdf/typescript/index.js';
export { convertOscalSarToHdf } from '../converters/oscal-to-hdf/typescript/index.js';
export { detectOscalDocumentType } from '../converters/oscal-to-hdf/typescript/index.js';
