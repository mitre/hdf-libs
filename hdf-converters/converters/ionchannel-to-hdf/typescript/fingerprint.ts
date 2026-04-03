/**
 * Ion Channel format fingerprint.
 *
 * Detects Ion Channel analysis JSON by presence of fingerprint keys:
 * analysis_id, team_id, source, trigger_hash, and scan_summaries.
 * Returns 1.0 when 3+ keys match plus scan_summaries, 0.5 for fewer.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

function isIonChannelAnalysis(obj: Record<string, unknown>): number {
  const keys = ['analysis_id', 'team_id', 'source', 'trigger_hash'];
  let matches = 0;
  for (const key of keys) {
    if (key in obj) {
      matches++;
    }
  }
  if (matches === 0) return 0;
  // Require scan_summaries to differentiate from other formats
  if (!('scan_summaries' in obj)) return 0;
  return matches >= 3 ? 1.0 : 0.5;
}

export const ionchannelFingerprint: ConverterFingerprint = {
  id: 'ionchannel-to-hdf',
  label: 'Ion Channel',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) return 0;
    return isIonChannelAnalysis(input as Record<string, unknown>);
  },
};

export function register(): void {
  if (getFingerprint('ionchannel-to-hdf')) return;
  registerFingerprint(ionchannelFingerprint);
}
