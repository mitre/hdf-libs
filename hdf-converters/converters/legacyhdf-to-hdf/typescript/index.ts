/**
 * Legacy HDF (v1.0) to HDF v2.0 converter.
 *
 * Converts InSpec exec-json (the legacy HDF v1.0 format)
 * to the current HDF v2.0 schema.
 */

export {
  convertLegacyHdf,
  downgradeToLegacyHdf,
  isLegacyHdf,
  type LegacyHDFResults,
  type HDFV2Results,
  type LegacyProfile,
  type LegacyControl,
  type LegacyResult,
  type LegacyGroup,
  type LegacyDependency,
  type LegacyPlatform,
  type V2Baseline,
  type V2Requirement,
  type V2Result,
  type V2Group,
  type V2Dependency,
} from './converter.js';
