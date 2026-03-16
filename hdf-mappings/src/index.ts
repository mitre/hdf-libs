/**
 * @mitre/hdf-mappings
 *
 * Security framework mappings for the Heimdall Data Format (HDF).
 * Provides CCI↔NIST, OWASP→NIST mappings and NIST control descriptions.
 */

// CCI exports
export {
  getCCIDescription,
  getCCINistMappings,
  getAllCCIIds,
  cciExists,
  getNistCCIMappings,
  nistToCci,
} from './cci/index.js';

export type { CCIItem, CCIMappings, NistCCIMappings } from './cci/types.js';

// NIST exports
export {
  getNISTDescription,
  getAllNISTIds,
  nistExists,
  getNISTFamily,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
  DEFAULT_REMEDIATION_NIST_TAGS,
  DEFAULT_COMPONENT_MANAGEMENT_NIST_TAGS,
} from './nist/index.js';

export type { NISTDescriptions } from './nist/types.js';

// OWASP exports
export {
  getOwaspNistMapping,
  getOwaspNistControl,
  getOwaspName,
  getAllOwaspIds,
  owaspExists,
  getAllOwaspMappings,
} from './owasp/index.js';

export type { OwaspNistMapping, OwaspNistMappings } from './owasp/types.js';

// CWE exports
export {
  getCweNistMapping,
  getCweNistControl,
  getCweName,
  getAllCweIds,
  cweExists,
  getAllCweMappings,
} from './cwe/index.js';

export type { CweNistMapping, CweNistMappings } from './cwe/types.js';

// Nessus exports
export {
  getNessusNistControl,
  getNessusPluginFamilyMappings,
  getAllNessusPluginFamilies,
  nessusPluginFamilyExists,
  getAllNessusMappings,
} from './nessus/index.js';

export type { NessusNistMapping, NessusNistMappings } from './nessus/types.js';

// Nikto exports
export {
  getNiktoNistControl,
  getAllNiktoIds,
  niktoExists,
  getAllNiktoMappings,
} from './nikto/index.js';

export type { NiktoNistMappings } from './nikto/types.js';

// ScoutSuite exports
export {
  getScoutsuiteNistMapping,
  getScoutsuiteNistControl,
  getAllScoutsuiteRules,
  scoutsuiteRuleExists,
  getAllScoutsuiteMappings,
} from './scoutsuite/index.js';

export type { ScoutsuiteNistMapping, ScoutsuiteNistMappings } from './scoutsuite/types.js';

// AWS Config exports
export {
  getAwsConfigNistMappingByIdentifier,
  getAwsConfigNistMappingByName,
  getAwsConfigNistControlByIdentifier,
  getAwsConfigNistControlByName,
  getAllAwsConfigIdentifiers,
  getAllAwsConfigRuleNames,
  awsConfigIdentifierExists,
  awsConfigRuleNameExists,
  getAllAwsConfigMappings,
} from './awsconfig/index.js';

export type { AwsConfigNistMapping, AwsConfigNistMappings } from './awsconfig/types.js';
