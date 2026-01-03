/**
 * @mitre/hdf-converters
 *
 * Converters for security tool outputs and HDF format versions
 */

// HDF v1.0 to v2.0 converter
export {
  convertV1ToV2,
  isHDFV1,
  type HDFV1Results,
  type HDFV2Results,
} from './v1-to-v2/index.js';
