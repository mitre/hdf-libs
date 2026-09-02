/**
 * Explicit fingerprint registration for all converters.
 *
 * Consumers call registerAllFingerprints() once at startup.
 * This avoids side-effect imports that bundlers tree-shake away.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from './registry.js';

// JSON ingest converters
import { asffFingerprint } from '../../converters/asff-to-hdf/typescript/fingerprint.js';
import { awsConfigFingerprint } from '../../converters/aws-config-to-hdf/typescript/fingerprint.js';
import { checkovFingerprint } from '../../converters/checkov-to-hdf/typescript/fingerprint.js';
import { conveyorFingerprint } from '../../converters/conveyor-to-hdf/typescript/fingerprint.js';
import { csafVexFingerprint } from '../../converters/csaf-vex-to-hdf/typescript/fingerprint.js';
import { cyclonedxFingerprint } from '../../converters/cyclonedx-to-hdf/typescript/fingerprint.js';
import { cyclonedxVexFingerprint } from '../../converters/cyclonedx-vex-to-hdf/typescript/fingerprint.js';
import { deptrackFingerprint } from '../../converters/deptrack-to-hdf/typescript/fingerprint.js';
import { gitlabFingerprint } from '../../converters/gitlab-to-hdf/typescript/fingerprint.js';
import { gosecFingerprint } from '../../converters/gosec-to-hdf/typescript/fingerprint.js';
import { grypeFingerprint } from '../../converters/grype-to-hdf/typescript/fingerprint.js';
import { jfrogXrayFingerprint } from '../../converters/jfrog-xray-to-hdf/typescript/fingerprint.js';
import { kicsFingerprint } from '../../converters/kics-to-hdf/typescript/fingerprint.js';
import { msftDefenderCloudFingerprint } from '../../converters/msft-defender-cloud-to-hdf/typescript/fingerprint.js';
import { msftDefenderDevopsFingerprint } from '../../converters/msft-defender-devops-to-hdf/typescript/fingerprint.js';
import { msftDefenderEndpointFingerprint } from '../../converters/msft-defender-endpoint-to-hdf/typescript/fingerprint.js';
import { msftSecureScoreFingerprint } from '../../converters/msft-secure-score-to-hdf/typescript/fingerprint.js';
import { neuvectorFingerprint } from '../../converters/neuvector-to-hdf/typescript/fingerprint.js';
import { openvexFingerprint } from '../../converters/openvex-to-hdf/typescript/fingerprint.js';
import { sarifFingerprint } from '../../converters/sarif-to-hdf/typescript/fingerprint.js';
import { scoutsuiteFingerprint } from '../../converters/scoutsuite-to-hdf/typescript/fingerprint.js';
import { snykFingerprint } from '../../converters/snyk-to-hdf/typescript/fingerprint.js';
import { spdxVexFingerprint } from '../../converters/spdx-vex-to-hdf/typescript/fingerprint.js';
import { sonarqubeFingerprint } from '../../converters/sonarqube-to-hdf/typescript/fingerprint.js';
import { splunkFingerprint } from '../../converters/splunk-to-hdf/typescript/fingerprint.js';
import { trivyFingerprint } from '../../converters/trivy-to-hdf/typescript/fingerprint.js';
import { trufflehogFingerprint } from '../../converters/trufflehog-to-hdf/typescript/fingerprint.js';
import { twistlockFingerprint } from '../../converters/twistlock-to-hdf/typescript/fingerprint.js';

// JSON ingest converters (input is JSON despite tool names suggesting XML)
import { niktoFingerprint } from '../../converters/nikto-to-hdf/typescript/fingerprint.js';
import { zapFingerprint } from '../../converters/zap-to-hdf/typescript/fingerprint.js';

// XML ingest converters
import { burpsuiteFingerprint } from '../../converters/burpsuite-to-hdf/typescript/fingerprint.js';
import { dbprotectFingerprint } from '../../converters/dbprotect-to-hdf/typescript/fingerprint.js';
import { fortifyFingerprint } from '../../converters/fortify-to-hdf/typescript/fingerprint.js';
import { junitFingerprint } from '../../converters/junit-to-hdf/typescript/fingerprint.js';
import { nessusFingerprint } from '../../converters/nessus-to-hdf/typescript/fingerprint.js';
import { netsparkerFingerprint } from '../../converters/netsparker-to-hdf/typescript/fingerprint.js';
import { veracodeFingerprint } from '../../converters/veracode-to-hdf/typescript/fingerprint.js';
import { xccdfFingerprint } from '../../converters/xccdf-results-to-hdf/typescript/fingerprint.js';
import { cklFingerprint } from '../../converters/ckl-to-hdf/typescript/fingerprint.js';
import { cklbFingerprint } from '../../converters/cklb-to-hdf/typescript/fingerprint.js';

// Text/CSV ingest converters
import { prismaFingerprint } from '../../converters/prisma-to-hdf/typescript/fingerprint.js';

// HDF native detection
import { hdfFingerprint } from '../../converters/hdf-passthrough/typescript/fingerprint.js';
import { legacyHdfFingerprint } from '../../converters/legacyhdf-to-hdf/typescript/fingerprint.js';

// OSCAL converters (7 fingerprints in one array)
import { oscalFingerprints } from '../../converters/oscal-to-hdf/typescript/fingerprint.js';

// Export converters
import { hdfToCsvFingerprint } from '../../converters/hdf-to-csv/typescript/fingerprint.js';
import { hdfToXmlFingerprint } from '../../converters/hdf-to-xml/typescript/fingerprint.js';
import { hdfToOscalSarFingerprint } from '../../converters/hdf-to-oscal-sar/typescript/fingerprint.js';
import { hdfToOscalPoamFingerprint } from '../../converters/hdf-to-oscal-poam/typescript/fingerprint.js';

const allFingerprints: ConverterFingerprint[] = [
  // JSON ingest
  asffFingerprint,
  awsConfigFingerprint,
  cklbFingerprint,
  checkovFingerprint,
  conveyorFingerprint,
  csafVexFingerprint,
  cyclonedxFingerprint,
  cyclonedxVexFingerprint,
  deptrackFingerprint,
  gitlabFingerprint,
  gosecFingerprint,
  grypeFingerprint,
  jfrogXrayFingerprint,
  kicsFingerprint,
  msftDefenderCloudFingerprint,
  msftDefenderDevopsFingerprint,
  msftDefenderEndpointFingerprint,
  msftSecureScoreFingerprint,
  neuvectorFingerprint,
  openvexFingerprint,
  sarifFingerprint,
  scoutsuiteFingerprint,
  snykFingerprint,
  spdxVexFingerprint,
  sonarqubeFingerprint,
  splunkFingerprint,
  trivyFingerprint,
  trufflehogFingerprint,
  twistlockFingerprint,
  // JSON ingest (input is JSON despite tool names)
  niktoFingerprint,
  zapFingerprint,
  // XML ingest
  burpsuiteFingerprint,
  cklFingerprint,
  dbprotectFingerprint,
  fortifyFingerprint,
  junitFingerprint,
  nessusFingerprint,
  netsparkerFingerprint,
  veracodeFingerprint,
  xccdfFingerprint,
  // Text/CSV ingest
  prismaFingerprint,
  // HDF native
  hdfFingerprint,
  legacyHdfFingerprint,
  // OSCAL (7 fingerprints)
  ...oscalFingerprints,
  // Export converters
  hdfToCsvFingerprint,
  hdfToXmlFingerprint,
  hdfToOscalSarFingerprint,
  hdfToOscalPoamFingerprint,
];

/**
 * Register all known converter fingerprints.
 * Idempotent — safe to call multiple times or after _resetRegistry().
 */
export function registerAllFingerprints(): void {
  for (const fp of allFingerprints) {
    if (!getFingerprint(fp.id)) {
      registerFingerprint(fp);
    }
  }
}
