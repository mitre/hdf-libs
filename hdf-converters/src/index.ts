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
