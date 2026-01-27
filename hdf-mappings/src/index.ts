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
} from './cci/index.js';

export type { CCIItem, CCIMappings } from './cci/types.js';

// NIST exports
export {
  getNISTDescription,
  getAllNISTIds,
  nistExists,
  getNISTFamily,
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
