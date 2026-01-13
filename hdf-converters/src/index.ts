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
} from '../converters/legacyhdf/typescript/index.js';
