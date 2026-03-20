/**
 * Explicit fingerprint registration for all converters.
 *
 * Consumers call registerAllFingerprints() once at startup.
 * This avoids side-effect imports that bundlers tree-shake away.
 *
 * As converters add fingerprints (Phase 3), add them to the array below.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from './registry.js';

// Import fingerprint data from each converter
import { sarifFingerprint } from '../../converters/sarif-to-hdf/typescript/fingerprint.js';

// Add new fingerprints here as they are created (Phase 3 batches)
const allFingerprints: ConverterFingerprint[] = [
  sarifFingerprint,
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
