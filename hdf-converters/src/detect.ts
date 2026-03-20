/**
 * @mitre/hdf-converters/detect
 *
 * Sub-path entry point for format auto-detection.
 * Lightweight — no converter function imports in this path.
 *
 * Usage:
 *   import { registerAllFingerprints, detectConverter } from '@mitre/hdf-converters/detect';
 *   registerAllFingerprints();
 *   const result = detectConverter(rawInput);
 */

export { detectConverter, detectConverterAll, detectFamily, type DetectionResult } from '../shared/typescript/fingerprint.js';
export { registerAllFingerprints } from '../shared/typescript/register-all.js';
export {
  registerFingerprint,
  getFingerprints,
  getIngestFingerprints,
  getFingerprint,
  type ConverterFingerprint,
  type InputFamily,
  type ConverterDirection,
  type OutputType,
} from '../shared/typescript/registry.js';
