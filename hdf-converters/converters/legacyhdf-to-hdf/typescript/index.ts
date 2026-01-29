/**
 * Legacy HDF (v1.0) to HDF v2.0 converter.
 *
 * Converts HDF files from the legacy InSpec native format (v1.0)
 * to the current HDF v2.0 schema.
 */

export {
  convertV1ToV2,
  isHDFV1,
  type HDFV1Results,
  type HDFV2Results,
  type V1Profile,
  type V1Control,
  type V1Result,
  type V1Group,
  type V1Dependency,
  type V1Platform,
  type V2Baseline,
  type V2Requirement,
  type V2Result,
  type V2Group,
  type V2Dependency,
} from './converter.js';
