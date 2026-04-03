/**
 * Splunk HDF event format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects Splunk HDF events by checking for an array where items have
 * `meta.subtype` and `meta.guid` (the Splunk HDF pipeline event structure).
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const splunkFingerprint: ConverterFingerprint = {
  id: 'splunk-to-hdf',
  label: 'Splunk',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (!Array.isArray(input)) return 0;
    if (input.length === 0) return 0;
    const first = input[0] as Record<string, unknown> | undefined;
    if (!first || typeof first !== 'object') return 0;
    const meta = first.meta as Record<string, unknown> | undefined;
    if (!meta || typeof meta !== 'object') return 0;
    if (typeof meta.subtype === 'string' && typeof meta.guid === 'string') return 1.0;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('splunk-to-hdf')) return;
  registerFingerprint(splunkFingerprint);
}
